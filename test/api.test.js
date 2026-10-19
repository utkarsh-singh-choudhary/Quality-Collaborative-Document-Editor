import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import { openDb, seed } from '../server/db.js';
import { createApp, textToDoc } from '../server/app.js';

let app;
const login = async (email) => { const a = request.agent(app); const r = await a.post('/api/login').send({ email, password: 'demo1234' }); expect(r.status).toBe(200); return a; };
const content = { type: 'doc', content: [{ type: 'heading', attrs: { level: 1 }, content: [{ type: 'text', text: 'Hi' }] },
  { type: 'paragraph', content: [{ type: 'text', text: 'bold', marks: [{ type: 'bold' }, { type: 'underline' }] }] },
  { type: 'bulletList', content: [{ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'x' }] }] }] }] };

beforeEach(() => { const db = openDb(':memory:'); seed(db); seed(db); app = createApp(db); });

describe('documents', () => {
  it('requires login', async () => { expect((await request(app).get('/api/documents')).status).toBe(401); });
  it('creates, renames, persists rich content', async () => {
    const a = await login('alice@demo.test');
    const { body: d } = await a.post('/api/documents').send({});
    expect(d.role).toBe('owner');
    expect((await a.patch(`/api/documents/${d.id}`).send({ title: 'Plan', content })).status).toBe(200);
    const got = (await a.get(`/api/documents/${d.id}`)).body;
    expect(got.title).toBe('Plan'); expect(got.content).toEqual(content);
  });
  it('rejects bad titles and invalid content', async () => {
    const a = await login('alice@demo.test');
    const { body: d } = await a.post('/api/documents').send({});
    expect((await a.patch(`/api/documents/${d.id}`).send({ title: '   ' })).status).toBe(400);
    expect((await a.patch(`/api/documents/${d.id}`).send({ title: 'x'.repeat(200) })).status).toBe(400);
    expect((await a.patch(`/api/documents/${d.id}`).send({ content: { type: 'doc', content: [{ type: 'script' }] } })).status).toBe(400);
    expect((await a.get(`/api/documents/${d.id}`)).body.title).toBe('Untitled document');
  });
});

describe('sharing & authorization', () => {
  it('enforces viewer/editor/revoke and blocks strangers', async () => {
    const alice = await login('alice@demo.test'), bob = await login('bob@demo.test'), carol = await login('carol@demo.test');
    const { body: d } = await alice.post('/api/documents').send({});
    expect((await bob.get(`/api/documents/${d.id}`)).status).toBe(404);
    expect((await carol.patch(`/api/documents/${d.id}`).send({ title: 'x' })).status).toBe(404);
    expect((await bob.post(`/api/documents/${d.id}/shares`).send({ email: 'bob@demo.test', role: 'editor' })).status).toBe(404);
    expect((await alice.post(`/api/documents/${d.id}/shares`).send({ email: 'bob@demo.test', role: 'viewer' })).status).toBe(201);
    expect((await alice.post(`/api/documents/${d.id}/shares`).send({ email: 'bob@demo.test', role: 'viewer' })).status).toBe(409);
    expect((await bob.get(`/api/documents/${d.id}`)).body.role).toBe('viewer');
    expect((await bob.patch(`/api/documents/${d.id}`).send({ content })).status).toBe(403);
    expect((await bob.delete(`/api/documents/${d.id}`)).status).toBe(403);
    expect((await bob.get(`/api/documents/${d.id}/shares`)).status).toBe(403);
    expect((await alice.patch(`/api/documents/${d.id}/shares/u_bob`).send({ role: 'editor' })).status).toBe(200);
    expect((await bob.patch(`/api/documents/${d.id}`).send({ content })).status).toBe(200);
    expect((await alice.delete(`/api/documents/${d.id}/shares/u_bob`)).status).toBe(200);
    expect((await bob.get(`/api/documents/${d.id}`)).status).toBe(404);
    expect((await bob.patch(`/api/documents/${d.id}`).send({ content })).status).toBe(404);
  });
  it('lists owned vs shared separately (seed data)', async () => {
    const bob = await login('bob@demo.test');
    const r = (await bob.get('/api/documents')).body;
    expect(r.owned).toHaveLength(0); expect(r.shared[0].role).toBe('viewer');
  });
});

describe('import', () => {
  it('imports markdown into structured content', async () => {
    const a = await login('alice@demo.test');
    const r = await a.post('/api/documents/import').attach('file', Buffer.from('# Title\n\nHello\n\n- a\n- b\n\n1. one\n'), 'notes.md');
    expect(r.status).toBe(201); expect(r.body.title).toBe('notes');
    expect(r.body.content.content.map((n) => n.type)).toEqual(['heading', 'paragraph', 'bulletList', 'orderedList']);
    expect((await a.get(`/api/documents/${r.body.id}`)).status).toBe(200);
  });
  it('rejects bad files', async () => {
    const a = await login('alice@demo.test');
    expect((await a.post('/api/documents/import').attach('file', Buffer.from('x'), 'a.exe')).status).toBe(415);
    expect((await a.post('/api/documents/import').attach('file', Buffer.from('   \n'), 'a.txt')).status).toBe(422);
    expect((await a.post('/api/documents/import').attach('file', Buffer.from([0xff, 0xfe, 0xfa]), 'a.txt')).status).toBe(422);
    expect((await a.post('/api/documents/import').attach('file', Buffer.alloc(2 * 1024 * 1024 + 10, 97), 'big.txt')).status).toBe(413);
    expect((await a.post('/api/documents/import')).status).toBe(400);
  });
  it('plain text does not interpret markdown', () => { expect(textToDoc('# x', false).content[0].type).toBe('paragraph'); });
});
