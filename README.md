# Ajaia Docs — collaborative document editor (take-home build)

Express + SQLite (better-sqlite3) backend, Zod validation, Tiptap (ProseMirror) editor in a single static page.

## Run
```
npm install
npm run seed   # optional: server also seeds on boot; safe to rerun
npm start      # http://localhost:3000   (DB file: ./data.db, override with DB_PATH, PORT)
npm test
```
Demo accounts (password `demo1234`): alice@demo.test, bob@demo.test, carol@demo.test. Alice owns "Welcome", shared with Bob as viewer.

## What works
Create / rename / delete (owner, with confirm) / search; Tiptap bold, italic, underline, H1–H3, bullet + numbered lists stored as validated Tiptap JSON; debounced (800 ms) autosave with sequence guard so a stale response never shows "Saved" over newer edits; flush on navigation and `beforeunload`; import of `.txt`/`.md` (UTF-8, max 2 MB, extension + MIME + binary/empty checks; Markdown headings, bullet and numbered lists → structured content; no HTML ever parsed); owner/editor/viewer sharing with add, change role, revoke.

## Authorization
All rules live in `authorize()` in `server/app.js`. No access or missing → 404 (existence not leaked); read-only role attempting write → 403. Share management/delete are owner-only. Ids are never credentials.

## Security / limits (be honest)
- Auth is DEMO MODE: seeded accounts, scrypt hashes, httpOnly SameSite=Lax session cookie. No signup, no rate limiting, no password reset. Share-by-email reveals whether an email exists.
- No real-time collaboration: concurrent edits are last-write-wins.
- Tiptap is loaded from esm.sh at runtime (needs internet in the browser).
- Not implemented: DOCX import, export, version history, presence, comments, E2E browser tests.

## Deployment
`render.yaml` is a Render Blueprint (web service + 1 GB persistent disk at `/var/data`, `DB_PATH=/var/data/data.db`, `NODE_ENV=production`). Push the repo to GitHub, then Render > New > Blueprint. A disk requires a paid instance; on a free/ephemeral instance user-created data is lost on restart (seed accounts are recreated on boot). Tiptap is bundled in `public/vendor/tiptap.js` (rebuild with `npm run build:vendor`), so no CDN is needed at runtime. Demo credentials are public in this README, so do not put real data on a live demo.

## AI workflow note
Built with Claude; the design (single authorize policy, strict content allow-list, seq-guarded autosave) was chosen by me and covered by `test/api.test.js`.
