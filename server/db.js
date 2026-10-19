import Database from 'better-sqlite3';
import crypto from 'node:crypto';

export function openDb(file = process.env.DB_PATH || 'data.db') {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL,
      owner_id TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK(role IN ('viewer','editor')),
      created_at TEXT NOT NULL, UNIQUE(document_id, user_id));
    CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
    CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);
  `);
  return db;
}

export const hash = (pw) => {
  const s = crypto.randomBytes(16).toString('hex');
  return `${s}:${crypto.scryptSync(pw, s, 32).toString('hex')}`;
};
export const verify = (pw, h) => {
  const [s, k] = h.split(':');
  const a = Buffer.from(k, 'hex'), b = crypto.scryptSync(pw, s, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// Idempotent: fixed ids + INSERT OR IGNORE. DEMO ACCOUNTS ONLY (password: demo1234).
export function seed(db) {
  const ins = db.prepare('INSERT OR IGNORE INTO users(id,name,email,password_hash) VALUES (?,?,?,?)');
  for (const [id, name, email] of [['u_alice', 'Alice Demo', 'alice@demo.test'], ['u_bob', 'Bob Demo', 'bob@demo.test'], ['u_carol', 'Carol Demo', 'carol@demo.test']])
    if (!db.prepare('SELECT 1 FROM users WHERE id=?').get(id)) ins.run(id, name, email, hash('demo1234'));
  const t = new Date().toISOString();
  const content = JSON.stringify({ type: 'doc', content: [
    { type: 'heading', attrs: { level: 1 }, content: [{ type: 'text', text: 'Welcome to Ajaia Docs' }] },
    { type: 'paragraph', content: [{ type: 'text', text: 'This sample is owned by Alice and shared with Bob as a viewer.' }] }] });
  db.prepare('INSERT OR IGNORE INTO documents(id,title,content,owner_id,created_at,updated_at) VALUES (?,?,?,?,?,?)').run('d_welcome', 'Welcome', content, 'u_alice', t, t);
  db.prepare('INSERT OR IGNORE INTO shares(id,document_id,user_id,role,created_at) VALUES (?,?,?,?,?)').run('s_welcome_bob', 'd_welcome', 'u_bob', 'viewer', t);
}
