import http from 'node:http';
import {readFile} from 'node:fs/promises';
import handler from './api/index.js';
const assets={'/':'index.html','/admin':'index.html','/app.js':'app.js','/style.css':'style.css'};
const server=http.createServer(async(req,res)=>{if(req.url.startsWith('/api/'))return handler(req,res);const file=assets[req.url.split('?')[0]];if(!file){res.writeHead(404);return res.end('Not found');}try{const bytes=await readFile(new URL('./public/'+file,import.meta.url));res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.setHeader('X-Content-Type-Options','nosniff');res.end(bytes);}catch{res.writeHead(500);res.end('Unable to load application');}});
server.listen(process.env.PORT||3000,'0.0.0.0',()=>console.log('Cyber One: http://localhost:'+(process.env.PORT||3000)+' | Admin: /admin'));
setInterval(async()=>{if(!process.env.DATABASE_URL)try{const {transact,backup}=await import('./lib/store.js');await transact(s=>backup(s));}catch{console.error('Backup failed; check configuration and disk permissions.');}},600000).unref();
