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

// DB file (tối thiểu). Về lâu dài nên chuyển sang DB thật.
const DB_FILE = "./license-db.json";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-admin-key");
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

/** ===== Health check (để test nhanh) ===== */
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.post("/api/verify", (req, res) => {
  const { deviceId, license } = req.body || {};
  if (!deviceId || !license)
    return res.status(400).send("Missing deviceId/license");

  const p = parseLicense(license);
  if (!p) return res.status(400).send("Bad license format");

  // hạn dùng
  const today = yyyymmddToday();
  if (p.expiry < today) return res.status(403).send("Expired");

  // hash đúng?
  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return res.status(403).send("Invalid");

  // bind 1 license <-> 1 device
  const db = loadDB();
  const rec = db[license];

  //Chặn nếu thiết bị đã bị admin thu hồi
  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    return res.status(403).send("Device revoked");
  }

  if (!rec) {
    // Fallback: nếu vì lý do nào đó license chưa được tạo qua admin/generate
    db[license] = {
      deviceId,
      expiry: p.expiry,
      userId: "L_" + sha256Hex(String(license)).slice(0, 12),
      userName: "User",
      examDate: "", // ✅ NEW
      firstUsedAt: new Date().toISOString(),
    };
    saveDB(db);
    return res.json({
      ok: true,
      expiry: p.expiry,
      userId: db[license].userId || "",
      userName: db[license].userName,
      examDate: db[license].examDate || "", // ✅ NEW
      bound: true,
      firstBind: true,
    });
  }

  if (rec.deviceId !== deviceId) {
    return res.status(403).send("License already bound to another device");
  }

  return res.json({
    ok: true,
    expiry: p.expiry,
    userId: rec.userId || "",
    userName: rec.userName || "User",
    examDate: rec.examDate || "", // ✅ NEW
    bound: true,
    firstBind: false,
  });
});

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

// Admin generate (PHẢI khóa)
app.post("/api/admin/generate", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  // ✅ NEW: nhận thêm userName + examDate (examDate dạng YYYYMMDD, ví dụ 20260707)
  const { deviceId, expiry, userId, userName, examDate } = req.body || {};
  if (!deviceId || !expiry || !userId || !userName) {
    return res.status(400).send("Missing deviceId/expiry/userId/userName");
  }

  const hash = computeLicenseHash(deviceId, expiry);
  const license = `${expiry}-${hash}`;

  // ✅ lưu vào DB để sau này verify trả về userName + examDate
  const db = loadDB();
  db[license] = {
    deviceId,
    expiry,
    userId,
    userName,
    examDate: examDate || "", // ✅ NEW
    createdAt: new Date().toISOString(),
  };
  saveDB(db);

  // trả về license + userName + examDate
  res.json({ license, expiry, userId, userName, examDate: examDate || "" });
});

// Admin revoke device (PHẢI khóa)
app.post("/api/admin/revoke-device", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { deviceId, reason } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = loadDB();
  db.__revokedDevices = db.__revokedDevices || {};
  db.__revokedDevices[deviceId] = {
    reason: reason || "",
    at: new Date().toISOString(),
  };
  saveDB(db);

  res.json({ ok: true });
});

// Admin UN-revoke device (cấp lại quyền)
app.post("/api/admin/unrevoke-device", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { deviceId } = req.body || {};
  if (!deviceId) return res.status(400).send("Missing deviceId");

  const db = loadDB();
  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    delete db.__revokedDevices[deviceId];
    saveDB(db);
  }

  res.json({ ok: true });
});


// ==================== PROGRESS (3 lần 100% để hoàn thành) ====================
function getUserIdByAuth(deviceId, license) {
  const p = parseLicense(license);
  if (!p) return { ok: false, code: 400, msg: "Bad license format" };

  const today = yyyymmddToday();
  if (p.expiry < today) return { ok: false, code: 403, msg: "Expired" };

  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return { ok: false, code: 403, msg: "Invalid" };

  const db = loadDB();

  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    return { ok: false, code: 403, msg: "Device revoked" };
  }

  const rec = db[license];
  if (!rec) return { ok: false, code: 403, msg: "License not found" };
  if (rec.deviceId !== deviceId) {
    return { ok: false, code: 403, msg: "License already bound to another device" };
  }

  const userId = rec.userId || "";
  if (!userId) return { ok: false, code: 500, msg: "Missing userId on license record" };

  return { ok: true, db, userId };
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

// Lấy tiến độ nhiều bài 1 lần
app.post("/api/progress/get", (req, res) => {
  const { deviceId, license, testIds } = req.body || {};
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

  const auth = getUserIdByAuth(deviceId, license);
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
      percent: calcPercentFromPerfectCount(perfectCount),
      completed: perfectCount >= 3,
      updatedAt: rec.updatedAt || "",
    };
  }

  saveDB(db);
  return res.json({ ok: true, userId: auth.userId, data: out });
});

// Ghi nhận 1 lần 100% cho 1 bài
app.post("/api/progress/mark-perfect", (req, res) => {
  const { deviceId, license, testId, attemptId } = req.body || {};
  if (!deviceId || !license || !testId) {
    return res.status(400).send("Missing deviceId/license/testId");
  }

  const auth = getUserIdByAuth(deviceId, license);
  if (!auth.ok) return res.status(auth.code).send(auth.msg);

  const db = auth.db;
  db.__progress = db.__progress || {};
  const userBucket = (db.__progress[auth.userId] = db.__progress[auth.userId] || {});

  const tid = String(testId).trim();
  if (!tid) return res.status(400).send("Bad testId");

  const rec = (userBucket[tid] = userBucket[tid] || {
    perfectCount: 0,
    updatedAt: "",
    recentAttempts: [],
  });

  // chống cộng trùng do F5 / bấm lại
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
        percent: calcPercentFromPerfectCount(perfectCount),
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
  return res.json({
    ok: true,
    perfectCount,
    percent: calcPercentFromPerfectCount(perfectCount),
    completed: perfectCount >= 3,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("License server running :" + PORT));
