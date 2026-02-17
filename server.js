import express from "express";
import crypto from "crypto";
import fs from "fs";

const app = express();

/**
 * License server v2:
 * - Vẫn giữ verify theo "license + deviceId" như cũ.
 * - Thêm quản lý theo user (userId) + tiến độ học (progress) theo userId (đồng bộ mọi thiết bị).
 *
 * DB structure (license-db.json):
 * {
 *   "<license>": { deviceId, expiry, userId, userName, examDate, createdAt },
 *   "__users": {
 *      "<userId>": { userName, examDate, createdAt, devices: { "<deviceId>": { createdAt } } }
 *   },
 *   "__revokedDevices": { "<deviceId>": { reason, at } },
 *   "__progress": { "<userId>": { "<testId>": { perfectCount, updatedAt, recentAttempts } } }
 * }
 */

const SECRET = process.env.LICENSE_SECRET;
if (!SECRET) throw new Error("Missing env LICENSE_SECRET");

const ALLOW_ORIGIN =
  process.env.ALLOW_ORIGIN || "https://thangtran1998.github.io";
const ADMIN_KEY = process.env.ADMIN_KEY;

const DB_FILE = "./license-db.json";

/** ===== CORS ===== */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, x-admin-key"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json());

/** ===== DB ===== */
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return {};
  }
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function ensureRoot(db) {
  db.__users = db.__users || {};
  db.__revokedDevices = db.__revokedDevices || {};
  db.__progress = db.__progress || {};
  return db;
}

/** ===== Utils ===== */
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}
function computeLicenseHash(deviceId, expiry) {
  return sha256Hex(`${deviceId}|${expiry}|${SECRET}`);
}
function parseLicense(license) {
  const m = /^(\d{8})-([a-f0-9]{64})$/i.exec(String(license || "").trim());
  if (!m) return null;
  return { expiry: m[1], hash: m[2].toLowerCase() };
}
function yyyymmddToday() {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}
function requireAdmin(req, res) {
  if (!ADMIN_KEY) {
    res.status(500).send("Missing ADMIN_KEY on server");
    return false;
  }
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) {
    res.status(401).send("Unauthorized");
    return false;
  }
  return true;
}
function clampInt(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, Math.trunc(x)));
}
function percentFromCount(c) {
  if (c <= 0) return 0;
  if (c === 1) return 33;
  if (c === 2) return 67;
  return 100;
}
function makeUserId() {
  // UUID chuẩn, không trùng, không cần nghĩ trước
  return crypto.randomUUID();
}

/** ===== Auth helper (license + device) ===== */
function authByLicenseDevice(deviceId, license) {
  if (!deviceId || !license) return { ok: false, code: 400, msg: "Missing deviceId/license" };

  const p = parseLicense(license);
  if (!p) return { ok: false, code: 400, msg: "Bad license format" };

  const today = yyyymmddToday();
  if (p.expiry < today) return { ok: false, code: 403, msg: "Expired" };

  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return { ok: false, code: 403, msg: "Invalid" };

  const db = ensureRoot(loadDB());

  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    return { ok: false, code: 403, msg: "Device revoked" };
  }

  const rec = db[license];
  if (!rec) return { ok: false, code: 403, msg: "License not found" };
  if (rec.deviceId !== deviceId) {
    return { ok: false, code: 403, msg: "License already bound to another device" };
  }

  let userId = rec.userId || "";
  if (!userId) {
    // Legacy license (cũ) chưa có userId -> tự gán userId "ổn định" theo userName+examDate
    const base = `${rec.userName || "User"}|${rec.examDate || ""}`;
    userId = `LEG_${sha256Hex(base).slice(0, 16)}`;
    rec.userId = userId;
    // register user if missing
    db.__users[userId] = db.__users[userId] || {
      userName: rec.userName || "User",
      examDate: rec.examDate || "",
      createdAt: new Date().toISOString(),
      devices: {},
    };
    db.__users[userId].devices = db.__users[userId].devices || {};
    db.__users[userId].devices[deviceId] = db.__users[userId].devices[deviceId] || { createdAt: new Date().toISOString() };
    saveDB(db);
  }

  return { ok: true, db, rec, userId, expiry: p.expiry };
}

/** ===== Health ===== */
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/** ===== VERIFY ===== */
app.post("/api/verify", (req, res) => {
  const { deviceId, license } = req.body || {};
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

  const p = parseLicense(license);
  if (!p) return res.status(400).send("Bad license format");

  const today = yyyymmddToday();
  if (p.expiry < today) return res.status(403).send("Expired");

  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return res.status(403).send("Invalid");

  const db = ensureRoot(loadDB());

  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    return res.status(403).send("Device revoked");
  }

  const rec = db[license];
  if (!rec) return res.status(403).send("License not found");

  if (rec.deviceId !== deviceId) {
    return res.status(403).send("License already bound to another device");
  }

  // Legacy license (cũ) chưa có userId -> tự gán userId "ổn định" theo userName+examDate
  if (!rec.userId) {
    const base = `${rec.userName || "User"}|${rec.examDate || ""}`;
    rec.userId = `LEG_${sha256Hex(base).slice(0, 16)}`;
    db.__users[rec.userId] = db.__users[rec.userId] || {
      userName: rec.userName || "User",
      examDate: rec.examDate || "",
      createdAt: new Date().toISOString(),
      devices: {},
    };
    db.__users[rec.userId].devices = db.__users[rec.userId].devices || {};
    db.__users[rec.userId].devices[deviceId] = db.__users[rec.userId].devices[deviceId] || { createdAt: new Date().toISOString() };
    saveDB(db);
  }

  return res.json({
    ok: true,
    expiry: p.expiry,
    userId: rec.userId || "",
    userName: rec.userName || "User",
    examDate: rec.examDate || "",
    bound: true,
    firstBind: false,
  });
});

/** ===== Admin: Generate license =====
 * Input:
 *  - deviceId (required)
 *  - expiry   (required, YYYYMMDD)
 *  - userName (required)
 *  - examDate (optional)
 *  - userId   (optional)  // nếu không đưa -> server tự tạo userId mới (lần cấp đầu)
 *
 * Behavior:
 *  - Nếu userId đã tồn tại -> thêm thiết bị mới cho user đó
 *  - Nếu userId chưa tồn tại -> tạo user
 */
app.post("/api/admin/generate", (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { deviceId, expiry, userName, examDate, userId } = req.body || {};
  if (!deviceId || !expiry || !userName) {
    return res.status(400).send("Missing deviceId/expiry/userName");
  }

  const db = ensureRoot(loadDB());

  const uid = String(userId || "").trim() || makeUserId();

  // register / update user
  db.__users[uid] = db.__users[uid] || {
    userName,
    examDate: examDate || "",
    createdAt: new Date().toISOString(),
    devices: {},
  };
  // allow updating display fields (optional)
  db.__users[uid].userName = userName;
  db.__users[uid].examDate = examDate || db.__users[uid].examDate || "";

  // add device to user registry
  db.__users[uid].devices = db.__users[uid].devices || {};
  db.__users[uid].devices[deviceId] = db.__users[uid].devices[deviceId] || {
    createdAt: new Date().toISOString(),
  };

  const hash = computeLicenseHash(deviceId, expiry);
  const license = `${expiry}-${hash}`;

  // store license record (backward compatible)
  db[license] = {
    deviceId,
    expiry,
    userId: uid,
    userName,
    examDate: examDate || "",
    createdAt: new Date().toISOString(),
  };

  saveDB(db);

  res.json({
    ok: true,
    userId: uid,
    license,
    expiry,
    userName,
    examDate: examDate || "",
  });
});

/** ===== Admin: List user devices/licenses =====
 * Input: { userId }
 * Output: devices + latest license per device (computed)
 */
app.post("/api/admin/user-info", (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { userId } = req.body || {};
  const uid = String(userId || "").trim();
  if (!uid) return res.status(400).send("Missing userId");

  const db = ensureRoot(loadDB());
  const u = db.__users[uid];
  if (!u) return res.status(404).send("User not found");

  const devices = Object.keys(u.devices || {});
  // compute licenses belonging to this user
  const licenses = [];
  for (const [k, v] of Object.entries(db)) {
    if (k.startsWith("__")) continue;
    if (v && v.userId === uid) {
      licenses.push({ license: k, deviceId: v.deviceId, expiry: v.expiry, createdAt: v.createdAt || "" });
    }
  }

  res.json({
    ok: true,
    userId: uid,
    userName: u.userName || "",
    examDate: u.examDate || "",
    devices,
    licenses,
    revokedDevices: devices.filter(d => db.__revokedDevices && db.__revokedDevices[d]),
  });
});

/** ===== Admin: Revoke/Unrevoke device (giữ endpoint cũ) ===== */
app.post("/api/admin/revoke-device", (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { deviceId, reason } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = ensureRoot(loadDB());
  db.__revokedDevices[deviceId] = {
    reason: reason || "",
    at: new Date().toISOString(),
  };
  saveDB(db);

  res.json({ ok: true });
});

app.post("/api/admin/unrevoke-device", (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { deviceId } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = ensureRoot(loadDB());
  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    delete db.__revokedDevices[deviceId];
    saveDB(db);
  }

  res.json({ ok: true });
});

/** ===== Admin: Revoke/Unrevoke ALL devices of a user ===== */
app.post("/api/admin/revoke-user", (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { userId, reason } = req.body || {};
  const uid = String(userId || "").trim();
  if (!uid) return res.status(400).send("Missing userId");

  const db = ensureRoot(loadDB());
  const u = db.__users[uid];
  if (!u) return res.status(404).send("User not found");

  const devices = Object.keys(u.devices || {});
  for (const d of devices) {
    db.__revokedDevices[d] = { reason: reason || "Revoke user", at: new Date().toISOString() };
  }
  saveDB(db);
  res.json({ ok: true, devicesCount: devices.length });
});

app.post("/api/admin/unrevoke-user", (req, res) => {
  if (!requireAdmin(req, res)) return;

  const { userId } = req.body || {};
  const uid = String(userId || "").trim();
  if (!uid) return res.status(400).send("Missing userId");

  const db = ensureRoot(loadDB());
  const u = db.__users[uid];
  if (!u) return res.status(404).send("User not found");

  const devices = Object.keys(u.devices || {});
  for (const d of devices) {
    if (db.__revokedDevices[d]) delete db.__revokedDevices[d];
  }
  saveDB(db);
  res.json({ ok: true, devicesCount: devices.length });
});

/** ===== Progress: GET many test statuses (per userId) ===== */
app.post("/api/progress/get", (req, res) => {
  const { deviceId, license, testIds } = req.body || {};
  const auth = authByLicenseDevice(deviceId, license);
  if (!auth.ok) return res.status(auth.code).send(auth.msg);

  const db = auth.db;
  db.__progress = db.__progress || {};
  const userBucket = (db.__progress[auth.userId] = db.__progress[auth.userId] || {});
  const list = Array.isArray(testIds) ? testIds : [];

  const out = {};
  for (const id of list) {
    const tid = String(id || "").trim();
    if (!tid) continue;
    const rec = userBucket[tid] || { perfectCount: 0 };
    const perfectCount = clampInt(rec.perfectCount || 0, 0, 3);
    out[tid] = {
      perfectCount,
      percent: percentFromCount(perfectCount),
      completed: perfectCount >= 3,
      updatedAt: rec.updatedAt || "",
    };
  }

  saveDB(db);
  res.json({ ok: true, userId: auth.userId, data: out });
});

/** ===== Progress: MARK perfect (100%) ===== */
app.post("/api/progress/mark-perfect", (req, res) => {
  const { deviceId, license, testId, attemptId } = req.body || {};
  if (!testId) return res.status(400).send("Missing testId");

  const auth = authByLicenseDevice(deviceId, license);
  if (!auth.ok) return res.status(auth.code).send(auth.msg);

  const db = auth.db;
  db.__progress = db.__progress || {};
  const userBucket = (db.__progress[auth.userId] = db.__progress[auth.userId] || {});

  const tid = String(testId).trim();
  const rec = (userBucket[tid] = userBucket[tid] || {
    perfectCount: 0,
    updatedAt: "",
    recentAttempts: [],
  });

  const aId = String(attemptId || "").trim();
  rec.recentAttempts = Array.isArray(rec.recentAttempts) ? rec.recentAttempts : [];

  if (aId) {
    if (rec.recentAttempts.includes(aId)) {
      const perfectCount = clampInt(rec.perfectCount || 0, 0, 3);
      saveDB(db);
      return res.json({
        ok: true,
        deduped: true,
        perfectCount,
        percent: percentFromCount(perfectCount),
        completed: perfectCount >= 3,
      });
    }
    rec.recentAttempts.push(aId);
    if (rec.recentAttempts.length > 20) rec.recentAttempts.shift();
  }

  rec.perfectCount = clampInt((rec.perfectCount || 0) + 1, 0, 3);
  rec.updatedAt = new Date().toISOString();

  saveDB(db);
  const perfectCount = rec.perfectCount;

  res.json({
    ok: true,
    perfectCount,
    percent: percentFromCount(perfectCount),
    completed: perfectCount >= 3,
  });
});

/** ===== Optional: request reset log (giữ như cũ) ===== */
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("License server running :" + PORT));
