import { DatabaseSync } from "node:sqlite";
import path from "path";

const DB_PATH = path.join(process.cwd(), "auth.db");

const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

// Migrations for existing databases
try { db.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT"); } catch {}
try { db.exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0"); } catch {}

export interface User {
  id: number;
  username: string;
  password_hash: string;
  totp_secret: string | null;
  totp_enabled: number;
  created_at: string;
}

export const getUserByUsername = db.prepare("SELECT * FROM users WHERE username = ?");
export const getUserById = db.prepare("SELECT * FROM users WHERE id = ?");
export const createUser = db.prepare(
  "INSERT INTO users (username, password_hash) VALUES (?, ?)"
);
export const enableUserTotp = db.prepare(
  "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?"
);
export const disableUserTotp = db.prepare(
  "UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?"
);

export default db;
