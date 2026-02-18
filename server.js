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

// =====================
// FIX: Sử dụng relative path GIỐNG server.txt
// =====================
// Không dùng __dirname, dùng relative path "./"
const DB_FILE = "./license-db.json";  // Giống hệt server.txt

// Helper để log đường dẫn (debug)
console.log("Working directory:", process.cwd());
console.log("DB file path:", path.resolve(DB_FILE));

// =====================
// DB helpers
// =====================
function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      // Tạo DB mới nếu chưa có
      const newDB = {
        __revokedDevices: {},
        __revokedUsers: {},
        __users: {},
        __userDevices: {},
        __progress: {},
      };
      // Ghi ngay để tạo file
      fs.writeFileSync(DB_FILE, JSON.stringify(newDB, null, 2), "utf-8");
      return newDB;
    }
    
    const raw = fs.readFileSync(DB_FILE, "utf-8");
    const db = JSON.parse(raw);
    
    // Ensure all required sections exist
    db.__revokedDevices = db.__revokedDevices || {};
    db.__revokedUsers = db.__revokedUsers || {};
    db.__users = db.__users || {};
    db.__userDevices = db.__userDevices || {};
    db.__progress = db.__progress || {};
    
    return db;
  } catch (err) {
    console.error("Error loading DB:", err);
    // Return empty DB on error
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
  try {
    // Atomic write: ghi vào file tạm rồi rename
    const tempFile = DB_FILE + ".tmp";
    fs.writeFileSync(tempFile, JSON.stringify(db, null, 2), "utf-8");
    fs.renameSync(tempFile, DB_FILE);
    return true;
  } catch (err) {
    console.error("Error saving DB:", err);
    return false;
  }
}

// =====================
// Thêm API để kiểm tra trạng thái DB
// =====================
app.get("/api/admin/db-status", (req, res) => {
  try {
    const exists = fs.existsSync(DB_FILE);
    const stats = exists ? fs.statSync(DB_FILE) : null;
    
    res.json({
      ok: true,
      workingDir: process.cwd(),
      dbFile: path.resolve(DB_FILE),
      exists,
      size: stats?.size || 0,
      modified: stats?.mtime || null
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// =====================
// Thêm API backup/restore đơn giản
// =====================
app.post("/api/admin/backup-manual", adminOnly, (req, res) => {
  try {
    const db = loadDB();
    const backupFile = `./backup-${new Date().toISOString().replace(/:/g, '-')}.json`;
    fs.writeFileSync(backupFile, JSON.stringify(db, null, 2), "utf-8");
    res.json({ ok: true, backupFile });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ... (phần còn lại của code giữ nguyên, chỉ thay đổi cách loadDB/saveDB)

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

// ADMIN: revoke/unrevoke user
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

app.listen(PORT, () => console.log("Server running on port", PORT));