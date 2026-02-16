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
  if (!fs.existsSync(DB_FILE)) {
    return { users: {}, licenses: {}, __revokedDevices: {} };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));

    // migrate nhẹ: nếu file cũ là object license->rec thì chuyển sang raw.licenses
    if (!raw.users && !raw.licenses) {
      return {
        users: {},
        licenses: raw || {},
        __revokedDevices: raw.__revokedDevices || {},
      };
    }

    raw.users = raw.users || {};
    raw.licenses = raw.licenses || {};
    raw.__revokedDevices = raw.__revokedDevices || {};
    return raw;
  } catch {
    return { users: {}, licenses: {}, __revokedDevices: {} };
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
function makeUserId() {
  // ngắn gọn, đủ unique cho DB file
  return "U_" + crypto.randomBytes(6).toString("hex"); // ví dụ U_a1b2c3d4e5f6
}

function nowIso() {
  return new Date().toISOString();
}


/** ===== Health check (để test nhanh) ===== */
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.post("/api/verify", (req, res) => {
  const { deviceId, license } = req.body || {};
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

  const p = parseLicense(license);
  if (!p) return res.status(400).send("Bad license format");

  const db = loadDB();

  // Chặn nếu thiết bị bị revoke
  if (db.__revokedDevices && db.__revokedDevices[deviceId]) {
    return res.status(403).send("Device revoked");
  }

  // hạn dùng theo license format
  const today = yyyymmddToday();
  if (p.expiry < today) return res.status(403).send("Expired");

  // hash đúng (vẫn giữ chống share)
  const expected = computeLicenseHash(deviceId, p.expiry);
  if (expected !== p.hash) return res.status(403).send("Invalid");

  // lấy record license trong db.licenses
  db.licenses = db.licenses || {};
  const rec = db.licenses[license];

  // nếu chưa có record -> tạo tạm (khuyến nghị: luôn generate qua admin)
  if (!rec) {
    // tạo user “tạm” theo license (để không crash)
    const tempUserId = "U_" + sha256Hex(license).slice(0, 12);

    db.users = db.users || {};
    if (!db.users[tempUserId]) {
      db.users[tempUserId] = {
        userName: "User",
        examDate: "",
        userExpiry: p.expiry,     // mặc định theo license
        status: "ACTIVE",
        createdAt: nowIso(),
        updatedAt: nowIso(),
      };
    }

    db.licenses[license] = {
      deviceId,
      expiry: p.expiry,
      userId: tempUserId,
      createdAt: nowIso(),
      firstUsedAt: nowIso(),
    };
    saveDB(db);

    const u = db.users[tempUserId];
    if (u.status === "REVOKED") return res.status(403).send("User revoked");

    // nếu bạn muốn: userExpiry có thể override license expiry
    const effectiveExpiry = u.userExpiry || p.expiry;
    if (effectiveExpiry < today) return res.status(403).send("Expired");

    return res.json({
      ok: true,
      userId: tempUserId,
      userStatus: u.status,
      expiry: effectiveExpiry,
      userName: u.userName || "User",
      examDate: u.examDate || "",
      bound: true,
      firstBind: true,
    });
  }

  // check bind 1 license <-> 1 device
  if (rec.deviceId !== deviceId) {
    return res.status(403).send("License already bound to another device");
  }

  // user record
  const userId = rec.userId;
  db.users = db.users || {};
  const u = db.users[userId];

  // nếu user không tồn tại (data bẩn) -> tạo lại cho khỏi chết
  if (!u) {
    db.users[userId] = {
      userName: "User",
      examDate: "",
      userExpiry: rec.expiry,
      status: "ACTIVE",
      createdAt: nowIso(),
      updatedAt: nowIso(),
    };
    saveDB(db);
  }

  const user = db.users[userId];

  // revoke theo user
  if (user.status === "REVOKED") {
    return res.status(403).send("User revoked");
  }

  // hạn theo user (đây là chỗ “gia hạn theo nhóm”)
  const effectiveExpiry = user.userExpiry || rec.expiry || p.expiry;
  if (effectiveExpiry < today) return res.status(403).send("Expired");

  return res.json({
    ok: true,
    userId,
    userStatus: user.status || "ACTIVE",
    expiry: effectiveExpiry,
    userName: user.userName || "User",
    examDate: user.examDate || "",
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

app.post("/api/admin/generate", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  // NEW: userId optional
  const { deviceId, expiry, userId, userName, examDate, userExpiry } = req.body || {};
  if (!deviceId || !expiry) {
    return res.status(400).send("Missing deviceId/expiry");
  }

  const db = loadDB();
  db.users = db.users || {};
  db.licenses = db.licenses || {};

  // nếu chưa có userId -> tạo user mới
  const uid = userId || makeUserId();

  // upsert user
  const existed = db.users[uid];
  db.users[uid] = {
    userName: (userName || existed?.userName || "User").trim(),
    examDate: examDate || existed?.examDate || "",
    userExpiry: userExpiry || existed?.userExpiry || expiry, // default theo expiry license
    status: existed?.status || "ACTIVE",
    createdAt: existed?.createdAt || nowIso(),
    updatedAt: nowIso(),
  };

  const hash = computeLicenseHash(deviceId, expiry);
  const license = `${expiry}-${hash}`;

  // lưu license record thuộc user
  db.licenses[license] = {
    deviceId,
    expiry,
    userId: uid,
    createdAt: nowIso(),
  };

  saveDB(db);

  res.json({
    license,
    expiry,
    userId: uid,
    userName: db.users[uid].userName,
    examDate: db.users[uid].examDate,
    userExpiry: db.users[uid].userExpiry,
    status: db.users[uid].status,
  });
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
// Admin revoke USER (thu hồi theo nhóm)
app.post("/api/admin/revoke-user", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId, reason } = req.body || {};
  if (!userId) return res.status(400).send("Missing userId");

  const db = loadDB();
  db.users = db.users || {};
  if (!db.users[userId]) return res.status(404).send("User not found");

  db.users[userId].status = "REVOKED";
  db.users[userId].revokedReason = reason || "";
  db.users[userId].updatedAt = nowIso();
  saveDB(db);

  res.json({ ok: true });
});

// Admin un-revoke USER (cấp lại quyền theo nhóm)
app.post("/api/admin/unrevoke-user", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId } = req.body || {};
  if (!userId) return res.status(400).send("Missing userId");

  const db = loadDB();
  db.users = db.users || {};
  if (!db.users[userId]) return res.status(404).send("User not found");

  db.users[userId].status = "ACTIVE";
  delete db.users[userId].revokedReason;
  db.users[userId].updatedAt = nowIso();
  saveDB(db);

  res.json({ ok: true });
});
// Admin extend USER expiry (gia hạn theo nhóm)
app.post("/api/admin/extend-user", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  const { userId, userExpiry } = req.body || {};
  if (!userId || !userExpiry) return res.status(400).send("Missing userId/userExpiry");

  const db = loadDB();
  db.users = db.users || {};
  if (!db.users[userId]) return res.status(404).send("User not found");

  db.users[userId].userExpiry = userExpiry;
  db.users[userId].updatedAt = nowIso();
  saveDB(db);

  res.json({ ok: true, userId, userExpiry });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("License server running :" + PORT));
