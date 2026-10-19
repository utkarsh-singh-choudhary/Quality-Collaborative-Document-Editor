import express from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { verify } from './db.js';

const MAX_UPLOAD = 2 * 1024 * 1024;
const now = () => new Date().toISOString();
const NODES = new Set(['paragraph', 'heading', 'bulletList', 'orderedList', 'listItem', 'text', 'hardBreak', 'blockquote', 'codeBlock', 'horizontalRule']);
const MARKS = new Set(['bold', 'italic', 'underline', 'strike', 'code']);

function validNode(n, d = 0) {
  if (!n || typeof n !== 'object' || d > 30 || !NODES.has(n.type)) return false;
  if (n.type === 'text' && typeof n.text !== 'string') return false;
  if (n.marks && !(Array.isArray(n.marks) && n.marks.every((m) => m && MARKS.has(m.type)))) return false;
  if (n.content && !(Array.isArray(n.content) && n.content.every((c) => validNode(c, d + 1)))) return false;
  return true;
}
export const validDoc = (c) => !!c && c.type === 'doc' && Array.isArray(c.content) && c.content.every((n) => validNode(n)) && JSON.stringify(c).length <= MAX_UPLOAD * 2;

export function textToDoc(text, markdown) {
  const content = [];
  let list = null;
  const txt = (s) => (s.length ? [{ type: 'text', text: s }] : undefined);
  for (const raw of text.replace(/\r\n?/g, '\n').split('\n')) {
    const line = raw.trimEnd();
    let m;
    if (!line.trim()) { list = null; continue; }
    if (markdown && (m = line.match(/^(#{1,6})\s+(.*)$/))) { list = null; content.push({ type: 'heading', attrs: { level: Math.min(m[1].length, 3) }, content: txt(m[2]) }); }
    else if (markdown && (m = line.match(/^\s*[-*+]\s+(.*)$/))) {
      if (!list || list.type !== 'bulletList') { list = { type: 'bulletList', content: [] }; content.push(list); }
      list.content.push({ type: 'listItem', content: [{ type: 'paragraph', content: txt(m[1]) }] });
    } else if (markdown && (m = line.match(/^\s*\d+[.)]\s+(.*)$/))) {
      if (!list || list.type !== 'orderedList') { list = { type: 'orderedList', content: [] }; content.push(list); }
      list.content.push({ type: 'listItem', content: [{ type: 'paragraph', content: txt(m[1]) }] });
    } else { list = null; content.push({ type: 'paragraph', content: txt(line.trim()) }); }
  }
  return content.length ? { type: 'doc', content } : null;
}

const titleSchema = z.string().trim().min(1, 'Title cannot be empty').max(120, 'Title is too long (max 120)');
const shareSchema = z.object({ email: z.string().trim().toLowerCase().email(), role: z.enum(['viewer', 'editor']) });
const patchSchema = z.object({ title: titleSchema.optional(), content: z.any().optional() })
  .refine((b) => b.title !== undefined || b.content !== undefined, 'Nothing to update');

export function createApp(db) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '5mb' }));
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD, files: 1 } });

  // ---- authorization policy: single source of truth ----
  const roleOf = (docId, userId) => {
    const d = db.prepare('SELECT owner_id FROM documents WHERE id=?').get(docId);
    if (!d) return null;
    if (d.owner_id === userId) return 'owner';
    return db.prepare('SELECT role FROM shares WHERE document_id=? AND user_id=?').get(docId, userId)?.role ?? null;
  };
  const CAN = { read: ['owner', 'editor', 'viewer'], edit: ['owner', 'editor'], owner: ['owner'] };
  // Returns role, or sends 404 (missing/no access: indistinguishable) or 403 (can read but not do this).
  const authorize = (req, res, action) => {
    const role = roleOf(req.params.id, req.user.id);
    if (!role) { res.status(404).json({ error: 'Document not found' }); return null; }
    if (!CAN[action].includes(role)) { res.status(403).json({ error: 'You do not have permission to do this' }); return null; }
    return role;
  };
  const serialize = (d, role) => ({ id: d.id, title: d.title, content: JSON.parse(d.content), ownerId: d.owner_id, createdAt: d.created_at, updatedAt: d.updated_at, role });

  const cookie = (req, n) => (req.headers.cookie || '').split(';').map((s) => s.trim().split('=')).find(([k]) => k === n)?.[1];
  const requireUser = (req, res, next) => {
    const t = cookie(req, 'sid');
    const u = t && db.prepare('SELECT u.id,u.name,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(t);
    if (!u) return res.status(401).json({ error: 'Please sign in' });
    req.user = u; next();
  };
  const validId = (req, res, next) => (/^[\w-]{1,64}$/.test(req.params.id) ? next() : res.status(400).json({ error: 'Invalid id' }));

  // ---- auth (DEMO MODE: seeded accounts, scrypt-hashed passwords, httpOnly session cookie) ----
  app.post('/api/login', (req, res) => {
    const p = z.object({ email: z.string().trim().toLowerCase(), password: z.string() }).safeParse(req.body);
    const u = p.success && db.prepare('SELECT * FROM users WHERE email=?').get(p.data.email);
    if (!u || !verify(p.data.password, u.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions(token,user_id,created_at) VALUES (?,?,?)').run(token, u.id, now());
    res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
    res.json({ id: u.id, name: u.name, email: u.email });
  });
  app.post('/api/logout', (req, res) => {
    const t = cookie(req, 'sid');
    if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
    res.json({ ok: true });
  });
  app.get('/api/me', requireUser, (req, res) => res.json(req.user));

  // ---- documents ----
  app.get('/api/documents', requireUser, (req, res) => {
    const q = (req.query.q || '').toString().slice(0, 100).toLowerCase();
    const owned = db.prepare('SELECT id,title,updated_at,owner_id FROM documents WHERE owner_id=? ORDER BY updated_at DESC').all(req.user.id);
    const shared = db.prepare(`SELECT d.id,d.title,d.updated_at,d.owner_id,s.role,u.name AS owner_name FROM shares s
      JOIN documents d ON d.id=s.document_id JOIN users u ON u.id=d.owner_id WHERE s.user_id=? ORDER BY d.updated_at DESC`).all(req.user.id);
    const f = (l) => l.filter((d) => d.title.toLowerCase().includes(q));
    res.json({ owned: f(owned), shared: f(shared) });
  });

  const create = (ownerId, title, content) => {
    const id = crypto.randomUUID(), t = now();
    db.prepare('INSERT INTO documents(id,title,content,owner_id,created_at,updated_at) VALUES (?,?,?,?,?,?)').run(id, title, JSON.stringify(content), ownerId, t, t);
    return db.prepare('SELECT * FROM documents WHERE id=?').get(id);
  };
  app.post('/api/documents', requireUser, (req, res) => {
    const t = req.body?.title === undefined ? { success: true, data: 'Untitled document' } : titleSchema.safeParse(req.body.title);
    if (!t.success) return res.status(400).json({ error: t.error.issues[0].message });
    res.status(201).json(serialize(create(req.user.id, t.data, { type: 'doc', content: [{ type: 'paragraph' }] }), 'owner'));
  });

  app.post('/api/documents/import', requireUser, (req, res) => {
    upload.single('file')(req, res, (err) => {
      if (err) return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'File is larger than 2 MB' : 'Upload failed' });
      const f = req.file;
      if (!f) return res.status(400).json({ error: 'No file provided' });
      const ext = path.extname(f.originalname).toLowerCase();
      if (!['.txt', '.md'].includes(ext)) return res.status(415).json({ error: 'Only .txt and .md files are supported' });
      if (!['text/plain', 'text/markdown', 'text/x-markdown', 'application/octet-stream', ''].includes(f.mimetype)) return res.status(415).json({ error: 'Unsupported file type' });
      let text;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(f.buffer).replace(/^\uFEFF/, ''); }
      catch { return res.status(422).json({ error: 'File is not valid UTF-8 text' }); }
      if (text.includes('\u0000')) return res.status(422).json({ error: 'File appears to be binary' });
      const doc = textToDoc(text, ext === '.md');
      if (!doc) return res.status(422).json({ error: 'File is empty' });
      const title = path.basename(f.originalname, ext).trim().slice(0, 120) || 'Imported document';
      res.status(201).json(serialize(create(req.user.id, title, doc), 'owner'));
    });
  });

  app.get('/api/documents/:id', requireUser, validId, (req, res) => {
    const role = authorize(req, res, 'read'); if (!role) return;
    res.json(serialize(db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id), role));
  });

  app.patch('/api/documents/:id', requireUser, validId, (req, res) => {
    const role = authorize(req, res, 'edit'); if (!role) return;
    const p = patchSchema.safeParse(req.body);
    if (!p.success) return res.status(400).json({ error: p.error.issues[0].message });
    if (p.data.content !== undefined && !validDoc(p.data.content)) return res.status(400).json({ error: 'Invalid document content' });
    const cur = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
    db.prepare('UPDATE documents SET title=?, content=?, updated_at=? WHERE id=?').run(
      p.data.title ?? cur.title, p.data.content !== undefined ? JSON.stringify(p.data.content) : cur.content, now(), cur.id);
    res.json({ ok: true, updatedAt: db.prepare('SELECT updated_at FROM documents WHERE id=?').get(cur.id).updated_at });
  });

  app.delete('/api/documents/:id', requireUser, validId, (req, res) => {
    if (!authorize(req, res, 'owner')) return;
    db.prepare('DELETE FROM documents WHERE id=?').run(req.params.id);
    res.json({ ok: true });
  });

  // ---- sharing (owner only) ----
  const listShares = (id) => db.prepare('SELECT u.id AS userId,u.name,u.email,s.role FROM shares s JOIN users u ON u.id=s.user_id WHERE s.document_id=? ORDER BY s.created_at').all(id);
  app.get('/api/documents/:id/shares', requireUser, validId, (req, res) => { if (authorize(req, res, 'owner')) res.json(listShares(req.params.id)); });
  app.post('/api/documents/:id/shares', requireUser, validId, (req, res) => {
    if (!authorize(req, res, 'owner')) return;
    const p = shareSchema.safeParse(req.body);
    if (!p.success) return res.status(400).json({ error: 'Provide a valid email and a role of viewer or editor' });
    const target = db.prepare('SELECT id FROM users WHERE email=?').get(p.data.email);
    if (!target) return res.status(404).json({ error: 'No user with that email' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'You already own this document' });
    if (db.prepare('SELECT 1 FROM shares WHERE document_id=? AND user_id=?').get(req.params.id, target.id)) return res.status(409).json({ error: 'Already shared with this user' });
    db.prepare('INSERT INTO shares(id,document_id,user_id,role,created_at) VALUES (?,?,?,?,?)').run(crypto.randomUUID(), req.params.id, target.id, p.data.role, now());
    res.status(201).json(listShares(req.params.id));
  });
  app.patch('/api/documents/:id/shares/:userId', requireUser, validId, (req, res) => {
    if (!authorize(req, res, 'owner')) return;
    const p = z.object({ role: z.enum(['viewer', 'editor']) }).safeParse(req.body);
    if (!p.success) return res.status(400).json({ error: 'Role must be viewer or editor' });
    const r = db.prepare('UPDATE shares SET role=? WHERE document_id=? AND user_id=?').run(p.data.role, req.params.id, req.params.userId);
    if (!r.changes) return res.status(404).json({ error: 'Collaborator not found' });
    res.json(listShares(req.params.id));
  });
  app.delete('/api/documents/:id/shares/:userId', requireUser, validId, (req, res) => {
    if (!authorize(req, res, 'owner')) return;
    const r = db.prepare('DELETE FROM shares WHERE document_id=? AND user_id=?').run(req.params.id, req.params.userId);
    if (!r.changes) return res.status(404).json({ error: 'Collaborator not found' });
    res.json(listShares(req.params.id));
  });

  app.use(express.static(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public')));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((err, req, res, next) => { // no stack traces to clients
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
    if (err instanceof SyntaxError) return res.status(400).json({ error: 'Malformed JSON' });
    console.error(err); res.status(500).json({ error: 'Internal server error' });
  });
  return app;
}
