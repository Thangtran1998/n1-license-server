import express from "express";
import crypto from "crypto";
import fs from "fs";

const app = express();

/**
 * ===== CONFIG =====
 * - SECRET: bắt buộc set bằng ENV trên Render
 * - ALLOW_ORIGIN: domain được phép gọi API (GitHub Pages của anh)
 * - ADMIN_KEY: khóa endpoint generate
 */
const SECRET = process.env.LICENSE_SECRET;
if (!SECRET) {
  throw new Error("Missing env LICENSE_SECRET");
}

const ALLOW_ORIGIN =
  process.env.ALLOW_ORIGIN || "https://thangtran1998.github.io";
const ADMIN_KEY = process.env.ADMIN_KEY; // bắt buộc set trên production

// DB file (giữ nguyên vị trí từ server.txt)
const DB_FILE = "./license-db.json";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-admin-key");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "1mb" }));

/** ===== DB Helpers ===== */
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    return {
      __revokedDevices: {},
      __revokedUsers: {},
      __users: {},
      __userDevices: {},
      __progress: {},      // progress theo userId
    };
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    // Đảm bảo các trường mới tồn tại
    db.__revokedDevices = db.__revokedDevices || {};
    db.__revokedUsers = db.__revokedUsers || {};
    db.__users = db.__users || {};
    db.__userDevices = db.__userDevices || {};
    db.__progress = db.__progress || {};  // CHIA SẺ: progress theo userId
    return db;
  } catch {
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
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

/** ===== Utils ===== */
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function computeLicenseHash(deviceId, expiry) {
  // Chỉ lấy 24 ký tự đầu cho format N1.YYYYMMDD.24char
  return sha256Hex(`${deviceId}|${expiry}|${SECRET}`).slice(0, 24);
}

function parseLicense(license) {
  // Hỗ trợ cả format cũ (yyyymmdd-hash64) và format mới (N1.yyyymmdd.hash24)
  const s = String(license || "").trim();
  
  // Format cũ: 20261231-hash64
  const oldFormat = /^(\d{8})-([a-f0-9]{64})$/i.exec(s);
  if (oldFormat) {
    return { expiry: oldFormat[1], hash: oldFormat[2].toLowerCase() };
  }
  
  // Format mới: N1.20261231.hash24
  const parts = s.split(".");
  if (parts.length === 3 && parts[0] === "N1") {
    const expiry = parts[1];
    const hash = parts[2];
    if (/^\d{8}$/.test(expiry) && /^[a-f0-9]{24}$/i.test(hash)) {
      return { expiry, hash };
    }
  }
  
  return null;
}

function yyyymmddToday() {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

/** ===== User Helpers ===== */
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
  
  // Đảm bảo mỗi user có object progress riêng (CHIA SẺ CHO ALL DEVICES)
  db.__progress[userId] = db.__progress[userId] || {};
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

/** ===== Progress Helpers ===== */
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

/**
 * Kiểm tra license và trả về userId nếu hợp lệ
 */
function verifyAndGetUserId(db, deviceId, license) {
  const p = parseLicense(license);
  if (!p) return { ok: false, code: 400, msg: "Bad license format" };

  const today = yyyymmddToday();
  if (p.expiry < today) return { ok: false, code: 403, msg: "Expired" };

  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return { ok: false, code: 403, msg: "Invalid" };

  const rec = db[license];
  if (!rec) return { ok: false, code: 403, msg: "License not found" };
  
  if (rec.deviceId !== deviceId) {
    return { ok: false, code: 403, msg: "License bound to another device" };
  }

  const userId = rec.userId || "";
  if (!userId) return { ok: false, code: 500, msg: "License missing userId" };

  if (isDeviceRevoked(db, deviceId)) {
    return { ok: false, code: 403, msg: "Device revoked" };
  }
  
  if (isUserRevoked(db, userId)) {
    return { ok: false, code: 403, msg: "User revoked" };
  }

  return { ok: true, userId, rec };
}

/** ===== Health check ===== */
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/** ===== Verify License ===== */
app.post("/api/verify", (req, res) => {
  const { deviceId, license } = req.body || {};
  if (!deviceId || !license)
    return res.status(400).send("Missing deviceId/license");

  const db = loadDB();
  const auth = verifyAndGetUserId(db, deviceId, license);
  
  if (!auth.ok) {
    return res.status(auth.code).send(auth.msg);
  }

  // Cập nhật last seen
  attachDeviceToUser(db, auth.userId, deviceId);
  saveDB(db);

  const userInfo = db.__users[auth.userId] || {};
  
  return res.json({
    ok: true,
    userId: auth.userId,
    expiry: auth.rec.expiry,
    userName: userInfo.userName || "User",
    examDate: userInfo.examDate || "",
    bound: true,
  });
});

/** ===== Request Reset ===== */
app.post("/api/request-reset", (req, res) => {
  const { deviceId, oldLicense, note } = req.body || {};
  console.log("[RESET REQUEST]", {
    deviceId,
    oldLicense,
    note,
    at: new Date().toISOString(),
  });
  res.json({ ok: true });
});

/** ===== Admin: Generate License ===== */
app.post("/api/admin/generate", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { deviceId, expiry, userName, examDate, userId } = req.body || {};
  if (!deviceId || !expiry || !userName) {
    return res.status(400).send("Missing deviceId/expiry/userName");
  }

  if (!/^\d{8}$/.test(String(expiry))) {
    return res.status(400).send("Bad expiry format (yyyymmdd)");
  }

  const db = loadDB();

  // Tạo hoặc lấy userId
  let uid = normalizeUserId(userId);
  if (!uid) {
    uid = crypto.randomUUID().replace(/-/g, "").slice(0, 20);
  }

  // Tạo license với format mới (N1.expiry.hash24)
  const hash = computeLicenseHash(deviceId, expiry);
  const license = `N1.${expiry}.${hash}`;

  // Lưu license
  db[license] = {
    deviceId,
    expiry,
    userId: uid,
    createdAt: new Date().toISOString(),
  };

  // Cập nhật user records (userName, examDate được lưu trong __users)
  ensureUserRecord(db, uid, userName, examDate);
  attachDeviceToUser(db, uid, deviceId);
  
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

/** ===== Admin: Revoke Device ===== */
app.post("/api/admin/revoke-device", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { deviceId, reason } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = loadDB();
  db.__revokedDevices[deviceId] = {
    reason: String(reason || "revoked").slice(0, 200),
    at: new Date().toISOString(),
  };
  saveDB(db);

  res.json({ ok: true, deviceId, revoked: true });
});

/** ===== Admin: Unrevoke Device ===== */
app.post("/api/admin/unrevoke-device", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { deviceId } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = loadDB();
  delete db.__revokedDevices[deviceId];
  saveDB(db);

  res.json({ ok: true, deviceId, revoked: false });
});

/** ===== Admin: Revoke User ===== */
app.post("/api/admin/revoke-user", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId, reason } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  ensureUserRecord(db, uid);

  db.__revokedUsers[uid] = {
    reason: String(reason || "revoked").slice(0, 200),
    at: new Date().toISOString(),
  };
  saveDB(db);

  res.json({ ok: true, userId: uid, revoked: true });
});

/** ===== Admin: Unrevoke User ===== */
app.post("/api/admin/unrevoke-user", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  delete db.__revokedUsers[uid];
  saveDB(db);

  res.json({ ok: true, userId: uid, revoked: false });
});

/** ===== Admin: User Info ===== */
app.post("/api/admin/user-info", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  const user = db.__users[uid] || null;
  const devices = Object.keys((db.__userDevices[uid] && db.__userDevices[uid].devices) || {});
  
  const licenses = [];
  for (const [k, v] of Object.entries(db)) {
    if (k.startsWith("__")) continue;
    if (v && v.userId === uid) {
      licenses.push({
        license: k,
        deviceId: v.deviceId,
        expiry: v.expiry,
        createdAt: v.createdAt,
      });
    }
  }

  // Lấy tiến độ của user
  const progress = db.__progress[uid] || {};

  res.json({
    ok: true,
    userId: uid,
    user,
    revoked: isUserRevoked(db, uid),
    devices: devices.map((d) => ({
      deviceId: d,
      revoked: isDeviceRevoked(db, d),
    })),
    licenses,
    progress, // Trả về tiến độ để admin xem
  });
});

/** ===== Progress: Get (CHIA SẺ CHO CÙNG USER ID) ===== */
app.post("/api/progress/get", (req, res) => {
  const { deviceId, license, testIds } = req.body || {};
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

  const db = loadDB();
  const auth = verifyAndGetUserId(db, deviceId, license);
  
  if (!auth.ok) {
    return res.status(auth.code).send(auth.msg);
  }

  // Cập nhật last seen
  attachDeviceToUser(db, auth.userId, deviceId);

  // Lấy progress từ userId (CHIA SẺ CHO TẤT CẢ DEVICE CÙNG USER)
  db.__progress[auth.userId] = db.__progress[auth.userId] || {};
  const bucket = db.__progress[auth.userId];

  const list = Array.isArray(testIds) ? testIds : [];
  const out = {};
  for (const id of list) {
    const tid = String(id || "").trim();
    if (!tid) continue;
    const rec = bucket[tid] || { perfectCount: 0 };
    const perfectCount = clampInt(rec.perfectCount || 0, 0, 3);
    out[tid] = {
      perfectCount,
      percent: calcPercentFromPerfectCount(perfectCount),
      completed: perfectCount >= 3,
      updatedAt: rec.updatedAt || "",
    };
  }
  
  saveDB(db);
  res.json({ 
    ok: true, 
    userId: auth.userId, 
    data: out 
  });
});

/** ===== Progress: Mark Perfect (CHIA SẺ CHO CÙNG USER ID) ===== */
app.post("/api/progress/mark-perfect", (req, res) => {
  const { deviceId, license, testId, attemptId } = req.body || {};
  if (!deviceId || !license || !testId) {
    return res.status(400).send("Missing deviceId/license/testId");
  }

  const db = loadDB();
  const auth = verifyAndGetUserId(db, deviceId, license);
  
  if (!auth.ok) {
    return res.status(auth.code).send(auth.msg);
  }

  const tid = String(testId).trim();
  if (!tid) return res.status(400).send("Bad testId");

  // Cập nhật last seen
  attachDeviceToUser(db, auth.userId, deviceId);

  // Lấy progress từ userId (CHIA SẺ CHO TẤT CẢ DEVICE CÙNG USER)
  db.__progress[auth.userId] = db.__progress[auth.userId] || {};
  const bucket = db.__progress[auth.userId];

  const rec = (bucket[tid] = bucket[tid] || {
    perfectCount: 0,
    updatedAt: "",
    recentAttempts: [],
  });

  const aId = String(attemptId || "").trim();
  rec.recentAttempts = Array.isArray(rec.recentAttempts) ? rec.recentAttempts : [];
  
  // Kiểm tra attempt trùng lặp
  if (aId) {
    if (rec.recentAttempts.includes(aId)) {
      const perfectCount = clampInt(rec.perfectCount || 0, 0, 3);
      saveDB(db);
      return res.json({
        ok: true,
        deduped: true,
        perfectCount,
        percent: calcPercentFromPerfectCount(perfectCount),
        completed: perfectCount >= 3,
      });
    }
    rec.recentAttempts.push(aId);
    if (rec.recentAttempts.length > 20) rec.recentAttempts.shift();
  }

  // Tăng perfectCount (tối đa 3)
  rec.perfectCount = clampInt((rec.perfectCount || 0) + 1, 0, 3);
  rec.updatedAt = new Date().toISOString();
  
  saveDB(db);

  const perfectCount = rec.perfectCount;
  res.json({
    ok: true,
    perfectCount,
    percent: calcPercentFromPerfectCount(perfectCount),
    completed: perfectCount >= 3,
  });
});

/** ===== Progress: Reset for test (Admin only) ===== */
app.post("/api/admin/reset-progress", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId, testId } = req.body || {};
  const uid = normalizeUserId(userId);
  if (!uid) return res.status(400).send("Missing/Bad userId");

  const db = loadDB();
  
  if (!db.__progress[uid]) {
    return res.json({ ok: true, message: "No progress found" });
  }

  if (testId) {
    // Reset 1 test cụ thể
    const tid = String(testId).trim();
    if (db.__progress[uid][tid]) {
      delete db.__progress[uid][tid];
    }
  } else {
    // Reset all tests cho user
    db.__progress[uid] = {};
  }
  
  saveDB(db);
  
  res.json({ 
    ok: true, 
    userId: uid,
    testId: testId || "all",
    reset: true 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("License server running :" + PORT));