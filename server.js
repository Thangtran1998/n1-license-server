import fs from "fs";
import path from "path";
import crypto from "crypto";
import express from "express";
import { fileURLToPath } from "url";

const app = express();
app.use(express.json({ limit: "1mb" }));

// =====================
// CONFIG
// =====================
const PORT = process.env.PORT || 3000;
const LICENSE_SECRET = process.env.LICENSE_SECRET || "CHANGE_ME_SECRET";
const ADMIN_KEY = process.env.ADMIN_KEY || "CHANGE_ME_ADMIN_KEY";
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";

// __dirname for ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// DB file
const DB_PATH = path.join(__dirname, "license-db.json");

// =====================
// CORS
// =====================
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, x-admin-key");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// =====================
// DB helpers
// =====================
function loadDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf-8");
    const db = JSON.parse(raw);
    
    // Log số lượng licenses
    const licenses = Object.keys(db).filter(k => !k.startsWith('__'));
    console.log(`Loaded DB with ${licenses.length} licenses`);
    
    db.__revokedDevices = db.__revokedDevices || {};
    db.__revokedUsers = db.__revokedUsers || {};
    db.__users = db.__users || {};
    db.__userDevices = db.__userDevices || {};
    db.__progress = db.__progress || {};
    
    return db;
  } catch (error) {
    console.log("Creating new DB, no existing file found");
    return {
      __revokedDevices: {},
      __revokedUsers: {},
      __users: {},
      __userDevices: {},
      __progress: {},
    };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf-8");
}

// =====================
// License helpers
// =====================
function yyyymmddToday() {
  const d = new Date();
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}${mm}${dd}`;
}

function computeLicenseHash(deviceId, expiry) {
  return crypto
    .createHmac("sha256", LICENSE_SECRET)
    .update(`${deviceId}|${expiry}`)
    .digest("hex")
    .slice(0, 24);
}

function parseLicense(license) {
  // Format: N1.<expiry>.<hash>
  if (!license || typeof license !== "string") return null;
  const parts = license.split(".");
  if (parts.length !== 3) return null;
  if (parts[0] !== "N1") return null;
  const expiry = parts[1];
  const hash = parts[2];
  if (!/^\d{8}$/.test(expiry)) return null;
  if (!/^[a-f0-9]{24}$/i.test(hash)) return null;
  return { expiry, hash };
}

function adminOnly(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_KEY) return res.status(401).send("Unauthorized");
  next();
}

// =====================
// User helpers
// =====================
function normalizeUserId(userId) {
  const s = String(userId || "").trim();
  if (!s) return "";
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(s)) return "";
  return s;
}

function ensureUserRecord(db, userId, userName, examDate) {
  db.__users[userId] = db.__users[userId] || {
    userName: String(userName || "").trim(),
    examDate: String(examDate || "").trim(),
    createdAt: new Date().toISOString(),
  };
  if (userName) db.__users[userId].userName = String(userName).trim();
  if (examDate) db.__users[userId].examDate = String(examDate).trim();
  db.__userDevices[userId] = db.__userDevices[userId] || { devices: {}, lastSeenAt: "" };
}

function attachDeviceToUser(db, userId, deviceId) {
  ensureUserRecord(db, userId);
  db.__userDevices[userId].devices[deviceId] = true;
  db.__userDevices[userId].lastSeenAt = new Date().toISOString();
}

function isUserRevoked(db, userId) {
  return !!(db.__revokedUsers && db.__revokedUsers[userId]);
}

function isDeviceRevoked(db, deviceId) {
  return !!(db.__revokedDevices && db.__revokedDevices[deviceId]);
}

// =====================
// AUTH for user actions
// =====================
function authFromDeviceLicense(db, deviceId, license) {
  const p = parseLicense(license);
  if (!p) return { ok: false, code: 400, msg: "Bad license format" };

  const today = yyyymmddToday();
  if (p.expiry < today) return { ok: false, code: 403, msg: "Expired" };

  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return { ok: false, code: 403, msg: "Invalid" };

  if (!db[license]) return { ok: false, code: 403, msg: "License not found" };
  const rec = db[license];
  if (rec.deviceId !== deviceId) return { ok: false, code: 403, msg: "License bound to another device" };

  const userId = rec.userId || "";
  if (!userId) return { ok: false, code: 500, msg: "License missing userId" };

  if (isDeviceRevoked(db, deviceId)) return { ok: false, code: 403, msg: "Device revoked" };
  if (isUserRevoked(db, userId)) return { ok: false, code: 403, msg: "User revoked" };

  attachDeviceToUser(db, userId, deviceId);
  saveDB(db);

  return { ok: true, userId, rec };
}

function clampInt(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, Math.trunc(x)));
}

function calcPercentFromPerfectCount(c) {
  if (c <= 0) return 0;
  if (c === 1) return 33;
  if (c === 2) return 67;
  return 100;
}

// =====================
// ROUTES
// =====================
app.get("/", (req, res) => res.send("OK"));

// ADMIN: generate license
app.post("/api/admin/generate", adminOnly, (req, res) => {
  const { deviceId, expiry, userId, userName, examDate } = req.body || {};
  if (!deviceId || !expiry || !userName) return res.status(400).send("Missing deviceId/expiry/userName");
  if (!/^\d{8}$/.test(String(expiry))) return res.status(400).send("Bad expiry format (yyyymmdd)");

  const db = loadDB();

  let uid = normalizeUserId(userId);
  if (!uid) uid = crypto.randomUUID().replace(/-/g, "").slice(0, 20);

  ensureUserRecord(db, uid, userName, examDate);
  attachDeviceToUser(db, uid, deviceId);

  const hash = computeLicenseHash(deviceId, expiry);
  const license = `N1.${expiry}.${hash}`;

  db[license] = {
    deviceId,
    expiry,
    userId: uid,
    userName: String(userName || "").trim(),
    examDate: String(examDate || "").trim(),
    createdAt: new Date().toISOString(),
  };

  saveDB(db);

  res.json({
    ok: true,
    license,
    expiry,
    userId: uid,
    userName: String(userName || "").trim(),
    examDate: String(examDate || "").trim(),
  });
});

// USER: verify
app.post("/api/verify", (req, res) => {
  const { deviceId, license } = req.body || {};
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

  const db = loadDB();
  const p = parseLicense(license);
  if (!p) return res.status(400).send("Bad license format");

  const today = yyyymmddToday();
  if (p.expiry < today) return res.status(403).send("Expired");

  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return res.status(403).send("Invalid");

  const rec = db[license];
  if (!rec) return res.status(403).send("License not found");
  if (rec.deviceId !== deviceId) return res.status(403).send("License bound to another device");

  const uid = rec.userId || "";
  if (!uid) return res.status(500).send("License missing userId");

  if (isDeviceRevoked(db, deviceId)) return res.status(403).send("Device revoked");
  if (isUserRevoked(db, uid)) return res.status(403).send("User revoked");

  attachDeviceToUser(db, uid, deviceId);
  saveDB(db);

  res.json({
    ok: true,
    userId: uid,
    userName: rec.userName || "",
    examDate: rec.examDate || "",
    expiry: rec.expiry || p.expiry,
  });
});

// ADMIN: revoke/unrevoke device
app.post("/api/admin/revoke-device", adminOnly, (req, res) => {
  const { deviceId, reason } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = loadDB();
  db.__revokedDevices[deviceId] = { reason: String(reason || "revoked").slice(0, 200), at: new Date().toISOString() };
  saveDB(db);
  res.json({ ok: true, deviceId, revoked: true });
});

app.post("/api/admin/unrevoke-device", adminOnly, (req, res) => {
  const { deviceId } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = loadDB();
  delete db.__revokedDevices[deviceId];
  saveDB(db);
  res.json({ ok: true, deviceId, revoked: false });
});

// ADMIN: revoke/unrevoke user (locks ALL devices)
app.post("/api/admin/revoke-user", adminOnly, (req, res) => {
  const { userId, reason } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  ensureUserRecord(db, uid);

  db.__revokedUsers[uid] = { reason: String(reason || "revoked").slice(0, 200), at: new Date().toISOString() };
  saveDB(db);
  res.json({ ok: true, userId: uid, revoked: true });
});

app.post("/api/admin/unrevoke-user", adminOnly, (req, res) => {
  const { userId } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  delete db.__revokedUsers[uid];
  saveDB(db);
  res.json({ ok: true, userId: uid, revoked: false });
});

// ADMIN: user-info
app.post("/api/admin/user-info", adminOnly, (req, res) => {
  const { userId } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  const user = db.__users[uid] || null;
  const devices = Object.keys((db.__userDevices[uid] && db.__userDevices[uid].devices) || {});
  const licenses = [];
  for (const [k, v] of Object.entries(db)) {
    if (k.startsWith("__")) continue;
    if (v && v.userId === uid) licenses.push({ license: k, deviceId: v.deviceId, expiry: v.expiry, createdAt: v.createdAt });
  }

  res.json({
    ok: true,
    userId: uid,
    user,
    revoked: isUserRevoked(db, uid),
    devices: devices.map((d) => ({ deviceId: d, revoked: isDeviceRevoked(db, d) })),
    licenses,
  });
});

// USER: progress get
app.post("/api/progress/get", (req, res) => {
  const { deviceId, license, testIds } = req.body || {};
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

  const db = loadDB();
  const auth = authFromDeviceLicense(db, deviceId, license);
  if (!auth.ok) return res.status(auth.code).send(auth.msg);

  db.__progress[auth.userId] = db.__progress[auth.userId] || {};
  const bucket = db.__progress[auth.userId];

  const list = Array.isArray(testIds) ? testIds : [];
  const out = {};
  for (const id of list) {
    const tid = String(id || "").trim();
    if (!tid) continue;
    const rec = bucket[tid] || { perfectCount: 0 };
    const perfectCount = clampInt(rec.perfectCount || 0, 0, 3);
    out[tid] = { perfectCount, percent: calcPercentFromPerfectCount(perfectCount), completed: perfectCount >= 3, updatedAt: rec.updatedAt || "" };
  }
  res.json({ ok: true, userId: auth.userId, data: out });
});

// USER: mark perfect
app.post("/api/progress/mark-perfect", (req, res) => {
  const { deviceId, license, testId, attemptId } = req.body || {};
  if (!deviceId || !license || !testId) return res.status(400).send("Missing deviceId/license/testId");

  const db = loadDB();
  const auth = authFromDeviceLicense(db, deviceId, license);
  if (!auth.ok) return res.status(auth.code).send(auth.msg);

  const tid = String(testId).trim();
  if (!tid) return res.status(400).send("Bad testId");

  db.__progress[auth.userId] = db.__progress[auth.userId] || {};
  const bucket = db.__progress[auth.userId];

  const rec = (bucket[tid] = bucket[tid] || { perfectCount: 0, updatedAt: "", recentAttempts: [] });

  const aId = String(attemptId || "").trim();
  rec.recentAttempts = Array.isArray(rec.recentAttempts) ? rec.recentAttempts : [];
  if (aId) {
    if (rec.recentAttempts.includes(aId)) {
      const perfectCount = clampInt(rec.perfectCount || 0, 0, 3);
      saveDB(db);
      return res.json({ ok: true, deduped: true, perfectCount, percent: calcPercentFromPerfectCount(perfectCount), completed: perfectCount >= 3 });
    }
    rec.recentAttempts.push(aId);
    if (rec.recentAttempts.length > 20) rec.recentAttempts.shift();
  }

  rec.perfectCount = clampInt((rec.perfectCount || 0) + 1, 0, 3);
  rec.updatedAt = new Date().toISOString();
  saveDB(db);

  const perfectCount = rec.perfectCount;
  res.json({ ok: true, perfectCount, percent: calcPercentFromPerfectCount(perfectCount), completed: perfectCount >= 3 });
});
// =====================
// DEBUG APIs - Kiểm tra DB
// =====================

// API 1: Xem tổng quan DB (admin only)
app.get("/api/admin/debug-db", adminOnly, (req, res) => {
  try {
    const db = loadDB();
    
    // Đếm số lượng licenses (các key không bắt đầu bằng __)
    const licenses = Object.keys(db).filter(k => !k.startsWith('__'));
    
    // Đếm số lượng users
    const users = Object.keys(db.__users || {});
    
    // Đếm số lượng devices đã revoke
    const revokedDevices = Object.keys(db.__revokedDevices || {});
    
    // Đếm số lượng users đã revoke
    const revokedUsers = Object.keys(db.__revokedUsers || {});
    
    // Lấy 5 license gần nhất (nếu có)
    const recentLicenses = licenses.slice(-5).map(licenseKey => {
      return {
        license: licenseKey,
        ...db[licenseKey]
      };
    });
    
    res.json({
      ok: true,
      timestamp: new Date().toISOString(),
      dbPath: DB_PATH,
      stats: {
        totalLicenses: licenses.length,
        totalUsers: users.length,
        revokedDevices: revokedDevices.length,
        revokedUsers: revokedUsers.length
      },
      recentLicenses: recentLicenses,
      sampleUsers: users.slice(0, 5)
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// API 2: Xem chi tiết một license cụ thể (admin only)
app.post("/api/admin/debug-license", adminOnly, (req, res) => {
  try {
    const { license } = req.body || {};
    if (!license) {
      return res.status(400).json({ ok: false, error: "Missing license" });
    }
    
    const db = loadDB();
    const licenseData = db[license];
    
    if (!licenseData) {
      return res.status(404).json({ 
        ok: false, 
        error: "License not found",
        note: "License keys are stored directly in DB root"
      });
    }
    
    // Kiểm tra xem user có bị revoke không
    const userId = licenseData.userId;
    const userRevoked = userId ? !!(db.__revokedUsers && db.__revokedUsers[userId]) : false;
    
    // Kiểm tra xem device có bị revoke không
    const deviceId = licenseData.deviceId;
    const deviceRevoked = deviceId ? !!(db.__revokedDevices && db.__revokedDevices[deviceId]) : false;
    
    res.json({
      ok: true,
      license: license,
      data: licenseData,
      status: {
        userRevoked,
        deviceRevoked,
        isValid: !userRevoked && !deviceRevoked
      }
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// API 3: Xem chi tiết user (admin only)
app.post("/api/admin/debug-user", adminOnly, (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) {
      return res.status(400).json({ ok: false, error: "Missing userId" });
    }
    
    const db = loadDB();
    
    // Thông tin user
    const userInfo = db.__users && db.__users[userId];
    
    // Các licenses của user
    const userLicenses = [];
    for (const [key, value] of Object.entries(db)) {
      if (!key.startsWith('__') && value.userId === userId) {
        userLicenses.push({
          license: key,
          deviceId: value.deviceId,
          expiry: value.expiry,
          createdAt: value.createdAt
        });
      }
    }
    
    // Devices của user
    const userDevices = db.__userDevices && db.__userDevices[userId];
    
    // Kiểm tra revoke status
    const isRevoked = !!(db.__revokedUsers && db.__revokedUsers[userId]);
    
    res.json({
      ok: true,
      userId: userId,
      userInfo: userInfo || { error: "User not found in __users" },
      isRevoked,
      licenses: userLicenses,
      devices: userDevices || { error: "No device info" },
      revokedInfo: isRevoked ? db.__revokedUsers[userId] : null
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// API 4: Kiểm tra file DB trực tiếp (admin only)
app.get("/api/admin/check-db-file", adminOnly, (req, res) => {
  try {
    // Kiểm tra file có tồn tại không
    const fileExists = fs.existsSync(DB_PATH);
    
    let fileStats = null;
    let fileContent = null;
    let fileSize = 0;
    
    if (fileExists) {
      fileStats = fs.statSync(DB_PATH);
      fileSize = fileStats.size;
      
      // Đọc 1KB đầu tiên để kiểm tra (tránh đọc file quá lớn)
      const fd = fs.openSync(DB_PATH, 'r');
      const buffer = Buffer.alloc(1024);
      fs.readSync(fd, buffer, 0, 1024, 0);
      fs.closeSync(fd);
      
      fileContent = buffer.toString('utf-8').substring(0, 200) + '...';
    }
    
    res.json({
      ok: true,
      dbPath: DB_PATH,
      fileExists,
      fileSize,
      fileStats: fileStats ? {
        created: fileStats.birthtime,
        modified: fileStats.mtime,
        size: fileStats.size
      } : null,
      filePreview: fileContent,
      directory: __dirname,
      directoryWritable: canWrite(__dirname)
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// Helper function để kiểm tra quyền ghi
function canWrite(dir) {
  try {
    fs.accessSync(dir, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

// API 5: Fix DB nếu cần (admin only)
app.post("/api/admin/fix-db", adminOnly, (req, res) => {
  try {
    const db = loadDB();
    
    // Fix cấu trúc __users nếu bị lỗi
    if (!db.__users || typeof db.__users !== 'object') {
      db.__users = {};
    }
    
    // Đảm bảo tất cả licenses đều có userId hợp lệ
    let fixedCount = 0;
    for (const [key, value] of Object.entries(db)) {
      if (key.startsWith('__')) continue;
      
      // Nếu license không có userId, tạo userId từ deviceId
      if (!value.userId) {
        value.userId = `auto_${value.deviceId || key.substring(0, 8)}`;
        fixedCount++;
      }
      
      // Đảm bảo user tồn tại trong __users
      if (value.userId && !db.__users[value.userId]) {
        db.__users[value.userId] = {
          userName: value.userName || 'Unknown',
          examDate: value.examDate || '',
          createdAt: value.createdAt || new Date().toISOString(),
          autoFixed: true
        };
        fixedCount++;
      }
    }
    
    saveDB(db);
    
    res.json({
      ok: true,
      message: `DB fixed. Updated ${fixedCount} records.`,
      fixedCount
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});
app.listen(PORT, () => {
  console.log("=".repeat(50));
  console.log(`Server running on port ${PORT}`);
  console.log(`DB Path: ${DB_PATH}`);
  console.log(`Admin Key: ${ADMIN_KEY === "CHANGE_ME_ADMIN_KEY" ? "⚠️ DEFAULT - CHANGE IT!" : "✅ Configured"}`);
  console.log(`License Secret: ${LICENSE_SECRET === "CHANGE_ME_SECRET" ? "⚠️ DEFAULT - CHANGE IT!" : "✅ Configured"}`);
  console.log(`CORS Allow Origin: ${ALLOW_ORIGIN}`);
  
  // Kiểm tra DB file
  try {
    const dbExists = fs.existsSync(DB_PATH);
    if (dbExists) {
      const stats = fs.statSync(DB_PATH);
      console.log(`DB File: ✅ Found (${stats.size} bytes)`);
      
      // Đọc thử để kiểm tra
      const db = loadDB();
      const licenseCount = Object.keys(db).filter(k => !k.startsWith('__')).length;
      console.log(`Licenses in DB: ${licenseCount}`);
    } else {
      console.log(`DB File: ❌ Not found - will be created on first write`);
    }
  } catch (e) {
    console.log(`DB File: ❌ Error checking - ${e.message}`);
  }
  
  console.log("=".repeat(50));
});
