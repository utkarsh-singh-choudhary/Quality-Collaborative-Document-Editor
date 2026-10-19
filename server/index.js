import { openDb, seed } from './db.js';
import { createApp } from './app.js';
const db = openDb();
seed(db);
const port = process.env.PORT || 3000;
createApp(db).listen(port, () => console.log(`Ajaia Docs on http://localhost:${port}`));
