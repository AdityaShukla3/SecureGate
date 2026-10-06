CREATE TABLE IF NOT EXISTS roles (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS permissions (id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS role_permissions (
 role_id INT REFERENCES roles(id) ON DELETE CASCADE,
 permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
 PRIMARY KEY (role_id, permission_id));
CREATE TABLE IF NOT EXISTS users (
 id SERIAL PRIMARY KEY,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role_id INT REFERENCES roles(id),
 created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS blocked_ips (
 ip TEXT PRIMARY KEY, reason TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_logs (
 id SERIAL PRIMARY KEY, user_id INT, ip TEXT, action TEXT, status TEXT,
 meta JSONB DEFAULT '{}', created_at TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);