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

const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "https://thangtran1998.github.io";
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
  if (!deviceId || !license) return res.status(400).send("Missing deviceId/license");

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
    userName: "User",
    firstUsedAt: new Date().toISOString()
  };
  saveDB(db);
  return res.json({ ok:true, expiry:p.expiry, userName: db[license].userName, bound:true, firstBind:true });
}


  if (rec.deviceId !== deviceId) {
    return res.status(403).send("License already bound to another device");
  }

  return res.json({
  ok: true,
  expiry: p.expiry,
  userName: rec.userName || "User",
  bound: true,
  firstBind: false
});

});


app.post("/api/request-reset", (req, res) => {
  const { deviceId, oldLicense, note } = req.body || {};
  console.log("[RESET REQUEST]", { deviceId, oldLicense, note, at: new Date().toISOString() });
  res.json({ ok: true });
});

// Admin generate (PHẢI khóa)
app.post("/api/admin/generate", (req, res) => {
  if (!ADMIN_KEY) return res.status(500).send("Missing ADMIN_KEY on server");
  const key = req.header("x-admin-key");
  if (key !== ADMIN_KEY) return res.status(401).send("Unauthorized");

  // ✅ NEW: nhận thêm userName
  const { deviceId, expiry, userName } = req.body || {};
  if (!deviceId || !expiry || !userName) {
    return res.status(400).send("Missing deviceId/expiry/userName");
  }

  const hash = computeLicenseHash(deviceId, expiry);
  const license = `${expiry}-${hash}`;

  // ✅ NEW: lưu vào DB để sau này verify trả về userName
  const db = loadDB();
  db[license] = {
    deviceId,
    expiry,
    userName,
    createdAt: new Date().toISOString()
  };
  saveDB(db);

  // trả về license + userName cho tiện
  res.json({ license, expiry, userName });
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
  db.__revokedDevices[deviceId] = { reason: reason || "", at: new Date().toISOString() };
  saveDB(db);

  res.json({ ok: true });
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("License server running :" + PORT));
