import { openDb, seed } from './db.js';
seed(openDb());
console.log('Seeded demo users: alice@demo.test, bob@demo.test, carol@demo.test (password demo1234)');
