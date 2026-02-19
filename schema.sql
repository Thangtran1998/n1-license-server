-- schema.sql - PostgreSQL schema for N1 License Server

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(100) PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    exam_date DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Licenses table
CREATE TABLE IF NOT EXISTS licenses (
    license VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id VARCHAR(255),
    expiry VARCHAR(8) NOT NULL, -- YYYYMMDD
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for faster lookups by user_id
CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses(user_id);

-- Index for device_id lookups
CREATE INDEX IF NOT EXISTS idx_licenses_device_id ON licenses(device_id) WHERE device_id IS NOT NULL;

-- Revoked devices
CREATE TABLE IF NOT EXISTS revoked_devices (
    device_id VARCHAR(255) PRIMARY KEY,
    reason TEXT,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Revoked users
CREATE TABLE IF NOT EXISTS revoked_users (
    user_id VARCHAR(100) PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    reason TEXT,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Progress tracking (perfect counts per test)
CREATE TABLE IF NOT EXISTS progress (
    user_id VARCHAR(100) PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    perfect JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);