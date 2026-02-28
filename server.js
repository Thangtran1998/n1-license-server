// server.js - N1 License Server for Neon.tech
import express from "express";
import pg from "pg";
import crypto from "crypto";
import dotenv from "dotenv";
import ws from "ws";
import { neonConfig } from "@neondatabase/serverless";

dotenv.config();

// =========================================================
// NEON CONFIG - QUAN TRỌNG: Cấu hình WebSocket
// =========================================================
neonConfig.webSocketConstructor = ws;
// Nếu chạy trên Render, có thể cần thêm dòng này:
neonConfig.useSecureWebSocket = true; // Dùng WSS thay vì WS

// =========================================================
// ENV VALIDATION
// =========================================================
const requiredEnv = ["LICENSE_SECRET", "ADMIN_KEY", "DATABASE_URL"];
for (const env of requiredEnv) {
  if (!process.env[env]) {
    console.error(`❌ Missing required ENV: ${env}`);
    process.exit(1);
  }
}

// =========================================================
// CONFIG
// =========================================================
const PORT = process.env.PORT || 3000;
const ALLOW_ORIGIN =
  process.env.ALLOW_ORIGIN || "https://thangtran1998.github.io";
const LICENSE_SECRET = process.env.LICENSE_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;
const ALLOW_FALLBACK_BIND = process.env.ALLOW_FALLBACK_BIND === "true";

console.log(`🚀 Starting N1 License Server (Neon.tech)`);
console.log(`📡 Port: ${PORT}`);
console.log(`🔗 CORS Allow-Origin: ${ALLOW_ORIGIN}`);
console.log(
  `🔒 Strict mode: ${ALLOW_FALLBACK_BIND ? "Fallback enabled" : "Strict mode"}`,
);
console.log(`📦 Database: Neon.tech PostgreSQL (WebSocket enabled)`);

// =========================================================
// PostgreSQL Pool - CẤU HÌNH CHO NEON
// =========================================================
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Neon yêu cầu SSL
  },
  max: 5, // Giới hạn connections cho free tier (Neon free cho phép 5 concurrent)
  idleTimeoutMillis: 10000, // Đóng connection không dùng sau 10s
  connectionTimeoutMillis: 5000, // Timeout sau 5s nếu không kết nối được
  allowExitOnIdle: true, // Cho phép pool đóng khi không dùng
});

// Handle pool errors
pool.on("error", (err) => {
  console.error("❌ Unexpected DB pool error:", err);
  // Không exit vì pool có thể reconnect
});

// Test connection with retry
async function testConnection(retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await pool.connect();
      console.log("✅ Database connected successfully to Neon.tech");
      client.release();
      return true;
    } catch (err) {
      console.error(
        `❌ Connection attempt ${i + 1}/${retries} failed:`,
        err.message,
      );
      if (i === retries - 1) {
        console.error("❌ Cannot connect to database after all retries");
        process.exit(1);
      }
      // Đợi 2s rồi thử lại
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

// Chạy test connection
await testConnection();

// =========================================================
// HELPER FUNCTIONS
// =========================================================

/**
 * Generate V1 license: YYYYMMDD-<sha256>
 */
function generateLicenseV1(deviceId, expiry, secret) {
  const hash = crypto
    .createHash("sha256")
    .update(`${deviceId}|${expiry}|${secret}`)
    .digest("hex");
  return `${expiry}-${hash}`;
}

/**
 * Validate V1 license
 */
function parseAndValidateV1(license, deviceId, secret) {
  const parts = license.split("-");
  if (parts.length !== 2) return { valid: false };
  const [expiry, hash] = parts;

  if (!/^\d{8}$/.test(expiry)) return { valid: false };

  const expectedHash = crypto
    .createHash("sha256")
    .update(`${deviceId}|${expiry}|${secret}`)
    .digest("hex");

  if (hash !== expectedHash) return { valid: false };

  return { valid: true, expiry, hash };
}

/**
 * Check if date string YYYYMMDD is >= today
 */
function isExpiryValid(expiryStr) {
  const today = new Date();
  const y = today.getFullYear();
  const m = String(today.getMonth() + 1).padStart(2, "0");
  const d = String(today.getDate()).padStart(2, "0");
  const todayStr = `${y}${m}${d}`;
  return expiryStr >= todayStr;
}

/**
 * Format date for response
 */
function formatDate(d) {
  if (!d) return null;
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

/**
 * CORS middleware
 */
function corsMiddleware(req, res, next) {
  res.header("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.header("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, x-admin-key");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
}

/**
 * Admin auth middleware
 */
function adminAuth(req, res, next) {
  const adminKey = req.headers["x-admin-key"];
  if (!adminKey || adminKey !== ADMIN_KEY) {
    return res.status(403).send("Forbidden: Invalid admin key");
  }
  next();
}

// =========================================================
// EXPRESS APP
// =========================================================
const app = express();
app.use(express.json());
app.use(corsMiddleware);

// =========================================================
// PUBLIC ENDPOINTS
// =========================================================

/**
 * GET /api/ping - Health check
 */
app.get("/api/ping", (req, res) => {
  res.json({
    ok: true,
    timestamp: new Date().toISOString(),
    mode: ALLOW_FALLBACK_BIND ? "fallback" : "strict",
    database: "neon.tech",
  });
});

/**
 * POST /api/verify - Verify license
 */
app.post("/api/verify", async (req, res) => {
  const { deviceId, license } = req.body;

  if (!deviceId || !license) {
    return res.status(400).send("Missing deviceId or license");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1. Parse and validate license format
    const parsed = parseAndValidateV1(license, deviceId, LICENSE_SECRET);
    if (!parsed.valid) {
      await client.query("ROLLBACK");
      return res.status(400).send("Invalid license format or hash");
    }

    const { expiry } = parsed;

    // 2. Check expiry date
    if (!isExpiryValid(expiry)) {
      await client.query("ROLLBACK");
      return res.status(400).send("Expired");
    }

    // 3. Check if license exists in DB
    const licenseQuery = await client.query(
      "SELECT license, user_id, device_id, created_at FROM licenses WHERE license = $1",
      [license],
    );

    if (licenseQuery.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("License not found");
    }

    const licenseRecord = licenseQuery.rows[0];
    const { user_id: userId, device_id: boundDeviceId } = licenseRecord;

    // 4. Check if device is revoked
    const revokedDevice = await client.query(
      "SELECT 1 FROM revoked_devices WHERE device_id = $1",
      [deviceId],
    );
    if (revokedDevice.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(403).send("Device revoked");
    }

    // 5. Check if user is revoked
    const revokedUser = await client.query(
      "SELECT 1 FROM revoked_users WHERE user_id = $1",
      [userId],
    );
    if (revokedUser.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(403).send("User revoked");
    }

    // 6. Check device binding
    const isFirstBind = !boundDeviceId;
    if (boundDeviceId && boundDeviceId !== deviceId) {
      await client.query("ROLLBACK");
      return res.status(403).send("License already bound to another device");
    }

    // 7. If first bind, update device_id
    if (isFirstBind) {
      await client.query(
        "UPDATE licenses SET device_id = $1 WHERE license = $2",
        [deviceId, license],
      );
    }

    // 8. Get user info
    const userQuery = await client.query(
      "SELECT user_name, exam_date FROM users WHERE user_id = $1",
      [userId],
    );

    await client.query("COMMIT");

    const user = userQuery.rows[0] || { user_name: null, exam_date: null };

    res.json({
      ok: true,
      expiry,
      userId,
      userName: user.user_name || "",
      examDate: user.exam_date ? formatDate(user.exam_date) : "",
      bound: !isFirstBind,
      firstBind: isFirstBind,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ /api/verify error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/progress/get - Get user progress
 */
app.post("/api/progress/get", async (req, res) => {
  const { deviceId, license, testIds } = req.body;

  if (!deviceId || !license) {
    return res.status(400).send("Missing deviceId or license");
  }

  const client = await pool.connect();

  try {
    // Verify license first
    const parsed = parseAndValidateV1(license, deviceId, LICENSE_SECRET);
    if (!parsed.valid) return res.status(400).send("Invalid license");

    const licenseQuery = await client.query(
      "SELECT user_id FROM licenses WHERE license = $1",
      [license],
    );

    if (licenseQuery.rows.length === 0) {
      return res.status(404).send("License not found");
    }

    const { user_id: userId } = licenseQuery.rows[0];

    // Check if user revoked
    const revoked = await client.query(
      "SELECT 1 FROM revoked_users WHERE user_id = $1",
      [userId],
    );
    if (revoked.rows.length > 0) {
      return res.status(403).send("User revoked");
    }

    // Get progress
    const progressQuery = await client.query(
      "SELECT perfect, updated_at FROM progress WHERE user_id = $1",
      [userId],
    );

    if (progressQuery.rows.length === 0) {
      return res.json({ ok: true, data: {} });
    }

    const { perfect, updated_at } = progressQuery.rows[0];

    // Filter only requested testIds if provided
    let result = perfect;
    if (Array.isArray(testIds) && testIds.length > 0) {
      result = {};
      for (const testId of testIds) {
        if (perfect[testId]) {
          result[testId] = perfect[testId];
        }
      }
    }

    res.json({
      ok: true,
      data: result,
      updatedAt: updated_at,
    });
  } catch (err) {
    console.error("❌ /api/progress/get error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/progress/mark-perfect - Mark a test as perfect
 */
app.post("/api/progress/mark-perfect", async (req, res) => {
  const { deviceId, license, moduleId } = req.body;

  if (!deviceId || !license || !moduleId) {
    return res.status(400).send("Missing deviceId, license or moduleId");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Verify license
    const parsed = parseAndValidateV1(license, deviceId, LICENSE_SECRET);
    if (!parsed.valid) {
      await client.query("ROLLBACK");
      return res.status(400).send("Invalid license");
    }

    const licenseQuery = await client.query(
      "SELECT user_id FROM licenses WHERE license = $1",
      [license],
    );

    if (licenseQuery.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("License not found");
    }

    const { user_id: userId } = licenseQuery.rows[0];

    // Check if user revoked
    const revoked = await client.query(
      "SELECT 1 FROM revoked_users WHERE user_id = $1",
      [userId],
    );
    if (revoked.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(403).send("User revoked");
    }

    // Get current progress
    const progressQuery = await client.query(
      "SELECT perfect FROM progress WHERE user_id = $1",
      [userId],
    );

    let perfectObj = {};
    if (progressQuery.rows.length > 0) {
      perfectObj = progressQuery.rows[0].perfect || {};
    }

    // Increment perfect count for this module
    if (!perfectObj[moduleId]) {
      perfectObj[moduleId] = { perfectCount: 1 };
    } else {
      perfectObj[moduleId].perfectCount =
        (perfectObj[moduleId].perfectCount || 0) + 1;
    }

    // Upsert progress
    if (progressQuery.rows.length > 0) {
      await client.query(
        "UPDATE progress SET perfect = $1, updated_at = NOW() WHERE user_id = $2",
        [JSON.stringify(perfectObj), userId],
      );
    } else {
      await client.query(
        "INSERT INTO progress (user_id, perfect, updated_at) VALUES ($1, $2, NOW())",
        [userId, JSON.stringify(perfectObj)],
      );
    }

    await client.query("COMMIT");

    res.json({
      ok: true,
      moduleId,
      perfectCount: perfectObj[moduleId].perfectCount,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ /api/progress/mark-perfect error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/request-reset - Log reset requests
 */
app.post("/api/request-reset", async (req, res) => {
  const { deviceId, oldLicense, note } = req.body;

  console.log("📋 RESET REQUEST:", {
    deviceId,
    oldLicense,
    note,
    timestamp: new Date().toISOString(),
  });

  res.json({
    ok: true,
    message: "Reset request logged. Admin will contact you.",
  });
});
// ==================== BOOKMARK API ====================
app.post("/api/bookmarks", async (req, res) => {
  try {
    const {
      id,
      questionKey,
      questionText,
      questionNumber,
      options,
      answer,
      detail,
      testId,
      userId,
      timestamp,
      note,
    } = req.body;

    // Kiểm tra field bắt buộc
    if (!id || !questionKey) {
      return res
        .status(400)
        .json({ ok: false, error: "Thiếu id hoặc questionKey" });
    }

    await pool.query(
      `INSERT INTO bookmarks 
  (id, question_key, question_text, question_number, options, answer, detail, test_id, user_id, timestamp, note)
 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
 ON CONFLICT (id) DO UPDATE SET
   note      = EXCLUDED.note,
   user_id   = EXCLUDED.user_id,
   options   = EXCLUDED.options,
   answer    = EXCLUDED.answer,
   detail    = EXCLUDED.detail,
   timestamp = EXCLUDED.timestamp`,
      [
        id,
        questionKey,
        (questionText || "").slice(0, 500),
        questionNumber || null,
        JSON.stringify(options || []),
        answer || null,
        detail || null,
        testId || null,
        userId || null,
        timestamp || Date.now(),
        note || "",
      ],
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("[BOOKMARK] Lỗi:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});
app.delete("/api/bookmarks/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ ok: false, error: "Thiếu id" });
    }

    const result = await pool.query("DELETE FROM bookmarks WHERE id = $1", [
      id,
    ]);

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ ok: false, error: "Không tìm thấy bookmark" });
    }

    res.json({ ok: true, deleted: id });
  } catch (err) {
    console.error("[BOOKMARK DELETE] Lỗi:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});
app.get("/api/bookmarks", async (req, res) => {
  try {
    const { userId, testId } = req.query;

    if (!userId || !testId) {
      return res
        .status(400)
        .json({ ok: false, error: "Thiếu userId hoặc testId" });
    }

    const result = await pool.query(
      "SELECT * FROM bookmarks WHERE user_id = $1 AND test_id = $2",
      [userId, testId],
    );

    res.json({ ok: true, bookmarks: result.rows });
  } catch (err) {
    console.error("[BOOKMARK GET] Lỗi:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// =========================================================
// ADMIN ENDPOINTS (Protected by x-admin-key)
// =========================================================

/**
 * POST /api/admin/generate - Generate new license
 */
app.post("/api/admin/generate", adminAuth, async (req, res) => {
  const { deviceId, expiry, userId, userName, examDate } = req.body;

  if (!deviceId || !expiry || !userId || !userName) {
    return res
      .status(400)
      .send("Missing required fields: deviceId, expiry, userId, userName");
  }

  if (!/^\d{8}$/.test(expiry)) {
    return res.status(400).send("Expiry must be YYYYMMDD");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Upsert user
    await client.query(
      `INSERT INTO users (user_id, user_name, exam_date, created_at) 
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id) 
       DO UPDATE SET user_name = EXCLUDED.user_name, exam_date = EXCLUDED.exam_date`,
      [userId, userName, examDate || null],
    );

    // Generate license
    const license = generateLicenseV1(deviceId, expiry, LICENSE_SECRET);

    // Insert license
    await client.query(
      `INSERT INTO licenses (license, user_id, device_id, expiry, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (license) DO NOTHING`,
      [license, userId, deviceId, expiry],
    );

    await client.query("COMMIT");

    res.json({
      ok: true,
      license,
      expiry,
      userId,
      userName,
      examDate: examDate || "",
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ /api/admin/generate error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/admin/user-info - Get full user info
 */
app.post("/api/admin/user-info", adminAuth, async (req, res) => {
  const { userId } = req.body;

  if (!userId) return res.status(400).send("Missing userId");

  const client = await pool.connect();

  try {
    // Get user
    const userQuery = await client.query(
      "SELECT user_name, exam_date, created_at FROM users WHERE user_id = $1",
      [userId],
    );

    const user = userQuery.rows[0] || null;

    // Check revoked
    const revokedQuery = await client.query(
      "SELECT 1 FROM revoked_users WHERE user_id = $1",
      [userId],
    );
    const revoked = revokedQuery.rows.length > 0;

    // Get devices (via licenses)
    const devicesQuery = await client.query(
      "SELECT DISTINCT device_id FROM licenses WHERE user_id = $1 AND device_id IS NOT NULL",
      [userId],
    );
    const devices = devicesQuery.rows.map((r) => r.device_id);

    // Get licenses
    const licensesQuery = await client.query(
      "SELECT license, device_id, expiry, created_at FROM licenses WHERE user_id = $1 ORDER BY created_at DESC",
      [userId],
    );
    const licenses = licensesQuery.rows.map((r) => ({
      license: r.license,
      deviceId: r.device_id,
      expiry: r.expiry,
      createdAt: r.created_at,
    }));

    // Get progress
    const progressQuery = await client.query(
      "SELECT perfect, updated_at FROM progress WHERE user_id = $1",
      [userId],
    );
    const progress = progressQuery.rows[0] || null;

    res.json({
      ok: true,
      userId,
      user: user
        ? {
            userName: user.user_name,
            examDate: user.exam_date ? formatDate(user.exam_date) : "",
            createdAt: user.created_at,
          }
        : null,
      revoked,
      devices,
      licenses,
      progress: progress
        ? {
            perfect: progress.perfect,
            updatedAt: progress.updated_at,
          }
        : null,
    });
  } catch (err) {
    console.error("❌ /api/admin/user-info error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/admin/revoke-device
 */
app.post("/api/admin/revoke-device", adminAuth, async (req, res) => {
  const { deviceId, reason } = req.body;

  if (!deviceId) return res.status(400).send("Missing deviceId");

  const client = await pool.connect();

  try {
    await client.query(
      `INSERT INTO revoked_devices (device_id, reason, revoked_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (device_id) DO NOTHING`,
      [deviceId, reason || "Revoked by admin"],
    );

    res.json({ ok: true, deviceId, revoked: true });
  } catch (err) {
    console.error("❌ /api/admin/revoke-device error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/admin/unrevoke-device
 */
app.post("/api/admin/unrevoke-device", adminAuth, async (req, res) => {
  const { deviceId } = req.body;

  if (!deviceId) return res.status(400).send("Missing deviceId");

  const client = await pool.connect();

  try {
    await client.query("DELETE FROM revoked_devices WHERE device_id = $1", [
      deviceId,
    ]);

    res.json({ ok: true, deviceId, revoked: false });
  } catch (err) {
    console.error("❌ /api/admin/unrevoke-device error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/admin/revoke-user
 */
app.post("/api/admin/revoke-user", adminAuth, async (req, res) => {
  const { userId, reason } = req.body;

  if (!userId) return res.status(400).send("Missing userId");

  const client = await pool.connect();

  try {
    await client.query(
      `INSERT INTO revoked_users (user_id, reason, revoked_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id) DO NOTHING`,
      [userId, reason || "Revoked by admin"],
    );

    res.json({ ok: true, userId, revoked: true });
  } catch (err) {
    console.error("❌ /api/admin/revoke-user error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/admin/unrevoke-user
 */
app.post("/api/admin/unrevoke-user", adminAuth, async (req, res) => {
  const { userId } = req.body;

  if (!userId) return res.status(400).send("Missing userId");

  const client = await pool.connect();

  try {
    await client.query("DELETE FROM revoked_users WHERE user_id = $1", [
      userId,
    ]);

    res.json({ ok: true, userId, revoked: false });
  } catch (err) {
    console.error("❌ /api/admin/unrevoke-user error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

/**
 * POST /api/admin/reset-progress - Clear user progress
 */
app.post("/api/admin/reset-progress", adminAuth, async (req, res) => {
  const { userId } = req.body;

  if (!userId) return res.status(400).send("Missing userId");

  const client = await pool.connect();

  try {
    await client.query("DELETE FROM progress WHERE user_id = $1", [userId]);

    res.json({ ok: true, userId, progressReset: true });
  } catch (err) {
    console.error("❌ /api/admin/reset-progress error:", err);
    res.status(500).send("Internal server error");
  } finally {
    client.release();
  }
});

// =========================================================
// START SERVER
// =========================================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`   📡 Listening on all interfaces (0.0.0.0)`);
  console.log(`📝 API endpoints:`);
  console.log(`   - GET  /api/ping`);
  console.log(`   - POST /api/verify`);
  console.log(`   - POST /api/progress/get`);
  console.log(`   - POST /api/progress/mark-perfect`);
  console.log(`   - POST /api/request-reset`);
  console.log(`   - POST /api/admin/* (protected)`);
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM received, closing pool...");
  await pool.end();
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("SIGINT received, closing pool...");
  await pool.end();
  process.exit(0);
});
