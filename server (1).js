// 흑백의 집 — 멀티플레이 서버 (외부 패키지 없음: Node 18+ 만 있으면 됨)
// - public/ 의 게임 파일을 그대로 제공
// - /ws 웹소켓: 로그인(닉네임+비밀번호), 접속자 위치·파티 상태 실시간 공유
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUBLIC_DIR = path.join(__dirname, 'public');
const ACC_FILE = path.join(DATA_DIR, 'accounts.json');

// ---------------- 계정 저장소 ----------------
let accounts = {};
try { fs.mkdirSync(DATA_DIR, { recursive: true }); accounts = JSON.parse(fs.readFileSync(ACC_FILE, 'utf8')); } catch (e) { accounts = {}; }
let saveTimer = null;
function saveAccounts() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = ACC_FILE + '.tmp';
    fs.writeFile(tmp, JSON.stringify(accounts), err => { if (!err) fs.rename(tmp, ACC_FILE, () => {}); });
  }, 500);
}
const tokens = new Map(); // 재접속용 토큰 -> 닉네임 (메모리)

function cleanStr(v, max) { return String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f​-‏‪-‮⁠-⁯﻿]/g, '').trim().slice(0, max); }
function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 32, { N: 16384, r: 8, p: 1 }).toString('hex'); }

function login(conn, nickRaw, pwRaw) {
  const now = Date.now();
  conn.tries = (conn.tries || []).filter(t => now - t < 60000);
  if (conn.tries.length >= 8) return { ok: false, err: '잠시 후 다시 시도하세요' };
  conn.tries.push(now);
  const nick = cleanStr(nickRaw, 10);
  const pw = String(pwRaw == null ? '' : pwRaw).slice(0, 64);
  if (nick.length < 2) return { ok: false, err: '닉네임을 입력하세요' };
  if (pw.length < 4) return { ok: false, err: '비밀번호를 4자 이상 입력하세요' };
  const key = nick.toLowerCase();
  let created = false;
  const acc = accounts[key];
  if (acc) {
    const h = Buffer.from(hashPw(pw, acc.salt), 'hex');
    const want = Buffer.from(acc.hash, 'hex');
    if (h.length !== want.length || !crypto.timingSafeEqual(h, want)) return { ok: false, err: '비밀번호가 틀렸어요' };
  } else {
    const salt = crypto.randomBytes(16).toString('hex');
    accounts[key] = { nick, salt, hash: hashPw(pw, salt), created: now };
    saveAccounts(); created = true;
  }
  conn.nick = accounts[key].nick;
  const token = crypto.randomBytes(24).toString('hex');
  tokens.set(token, conn.nick);
  conn.presence.nick = conn.nick; dirty = true;
  return { ok: true, created, token, nick: conn.nick };
}

// ---------------- 접속자 / 프레즌스 ----------------
const conns = new Map(); // peer -> conn
let dirty = false;
const PRES_KEYS = { where: 'str', rid: 'str', rname: 'str', rd: 'num', priv: 'bool', host: 'bool', phase: 'str', x: 'num', y: 'num' };
function applyPresence(conn, patch) {
  if (!patch || typeof patch !== 'object') return;
  for (const k of Object.keys(patch)) {
    const type = PRES_KEYS[k]; if (!type) continue;
    const v = patch[k];
    if (v === null) { delete conn.presence[k]; continue; }
    if (type === 'str' && typeof v === 'string') conn.presence[k] = cleanStr(v, 24);
    else if (type === 'num' && typeof v === 'number' && Number.isFinite(v) && Math.abs(v) < 1e7) conn.presence[k] = Math.round(v * 100) / 100;
    else if (type === 'bool' && typeof v === 'boolean') conn.presence[k] = v;
  }
  conn.presence.nick = conn.nick || null; // 닉네임은 로그인한 계정 것만
  dirty = true;
}
setInterval(() => {
  if (!dirty) return; dirty = false;
  const peers = [];
  for (const c of conns.values()) peers.push({ peer: c.peer, presence: c.presence });
  const msg = JSON.stringify({ t: 'peers', peers });
  for (const c of conns.values()) c.send(msg);
}, 100);

function onMessage(conn, text) {
  let m; try { m = JSON.parse(text); } catch (e) { return; }
  if (!m || typeof m !== 'object') return;
  if (m.t === 'presence') applyPresence(conn, m.patch);
  else if (m.t === 'login') conn.send(JSON.stringify(Object.assign({ t: 'login' }, login(conn, m.nick, m.pw))));
  else if (m.t === 'resume') {
    const nick = tokens.get(String(m.token || ''));
    if (nick) { conn.nick = nick; conn.presence.nick = nick; dirty = true; }
    conn.send(JSON.stringify({ t: 'resume', ok: !!nick, nick: nick || null }));
  }
}

// ---------------- 최소 웹소켓 구현 (RFC 6455) ----------------
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_PAYLOAD = 64 * 1024;
let nextId = 1;
function wsConnection(socket) {
  const conn = { peer: 'p' + (nextId++).toString(36) + crypto.randomBytes(3).toString('hex'), presence: {}, nick: null, alive: true, buf: Buffer.alloc(0), frags: [] };
  conn.send = (text) => {
    if (socket.destroyed) return;
    const data = Buffer.from(text, 'utf8'); const len = data.length;
    let head;
    if (len < 126) { head = Buffer.from([0x81, len]); }
    else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x81; head[1] = 126; head.writeUInt16BE(len, 2); }
    else { head = Buffer.alloc(10); head[0] = 0x81; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
    socket.write(Buffer.concat([head, data]));
  };
  const ctrl = (op, payload = Buffer.alloc(0)) => { if (!socket.destroyed) socket.write(Buffer.concat([Buffer.from([0x80 | op, payload.length]), payload])); };
  conn.ping = () => ctrl(0x9);
  const close = () => { if (conns.delete(conn.peer)) dirty = true; socket.destroy(); };
  socket.on('data', chunk => {
    conn.buf = Buffer.concat([conn.buf, chunk]);
    while (conn.buf.length >= 2) {
      const b0 = conn.buf[0], b1 = conn.buf[1];
      const fin = (b0 & 0x80) !== 0, op = b0 & 0x0f, masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (conn.buf.length < 4) return; len = conn.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (conn.buf.length < 10) return; const big = conn.buf.readBigUInt64BE(2); if (big > BigInt(MAX_PAYLOAD)) return close(); len = Number(big); off = 10; }
      if (len > MAX_PAYLOAD || !masked) return close();
      if (conn.buf.length < off + 4 + len) return;
      const mask = conn.buf.slice(off, off + 4); off += 4;
      const payload = Buffer.alloc(len);
      for (let i = 0; i < len; i++) payload[i] = conn.buf[off + i] ^ mask[i & 3];
      conn.buf = conn.buf.slice(off + len);
      if (op === 0x8) { ctrl(0x8); return close(); }
      if (op === 0x9) { ctrl(0xA, payload.slice(0, 125)); continue; }
      if (op === 0xA) { conn.alive = true; continue; }
      if (op === 0x1 || op === 0x0) {
        conn.frags.push(payload);
        if (conn.frags.reduce((a, p) => a + p.length, 0) > MAX_PAYLOAD) return close();
        if (fin) { const text = Buffer.concat(conn.frags).toString('utf8'); conn.frags = []; onMessage(conn, text); }
      }
    }
  });
  socket.on('close', close); socket.on('end', close); socket.on('error', close);
  conns.set(conn.peer, conn); dirty = true;
  conn.send(JSON.stringify({ t: 'welcome', peer: conn.peer }));
  return conn;
}
setInterval(() => {
  for (const c of conns.values()) { if (!c.alive) { c.send = () => {}; conns.delete(c.peer); dirty = true; continue; } c.alive = false; c.ping(); }
}, 25000);

// ---------------- HTTP ----------------
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
// 게임 파일 찾기: public/index.html 이 없어도 저장소 맨 위나 다른 이름의 .html 을 찾아서 씀
function findGamePage() {
  const tries = [path.join(PUBLIC_DIR, 'index.html'), path.join(__dirname, 'index.html')];
  for (const dir of [PUBLIC_DIR, path.join(__dirname, 'Public'), __dirname]) {
    try { for (const f of fs.readdirSync(dir)) if (/\.html?$/i.test(f)) tries.push(path.join(dir, f)); } catch (e) {}
  }
  for (const f of tries) { try { if (fs.statSync(f).isFile()) return f; } catch (e) {} }
  return null;
}
const server = http.createServer((req, res) => {
  const url = decodeURIComponent((req.url || '/').split('?')[0]);
  if (url === '/health') { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('ok ' + conns.size); }
  const page = findGamePage();
  if (!page) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    return res.end('게임 파일(index.html)을 찾지 못했어요. GitHub 저장소에 index.html 이 올라가 있는지 확인해 주세요.');
  }
  // 이미지 같은 다른 파일이 public 에 있으면 그대로 주고, 나머지는 전부 게임 화면으로
  const asked = path.normalize(path.join(PUBLIC_DIR, url));
  const send = (file) => fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(500); return res.end(); }
    res.writeHead(200, { 'content-type': TYPES[path.extname(file).toLowerCase()] || 'text/html; charset=utf-8', 'cache-control': 'no-cache' });
    res.end(data);
  });
  if (url !== '/' && asked.startsWith(PUBLIC_DIR + path.sep)) {
    fs.stat(asked, (err, st) => send(!err && st.isFile() ? asked : page));
  } else send(page);
});
server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if ((req.url || '').split('?')[0] !== '/ws' || !key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  wsConnection(socket);
});
server.listen(PORT, () => {
  console.log('흑백의 집 서버 실행 중: http://localhost:' + PORT);
  console.log('게임 파일: ' + (findGamePage() || '찾지 못함! index.html 을 올려 주세요'));
});
