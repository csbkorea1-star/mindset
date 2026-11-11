// Deployment bundle: account and storage modules are included in this file.
const createStorage = (() => {
const module={exports:{}};
'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
module.exports=function storage(){
  const context=new AsyncLocalStorage();let ready=Promise.resolve(),serial=Promise.resolve();
  if(process.env.DATABASE_URL){
    const {Pool,types}=require('pg');types.setTypeParser(20,Number);
    const pool=new Pool({connectionString:process.env.DATABASE_URL,max:4,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
    pool.on('error',()=>console.error('데이터베이스 연결이 종료되었습니다. 다음 요청에서 다시 연결합니다.'));
    const sql=text=>{let n=0;return text.replace(/\?/g,()=>'$'+(++n));};
    async function query(text,args=[]){await ready;return (context.getStore()||pool).query(sql(text),args);}
    return {kind:'postgres',
      init(schema){ready=pool.query(schema.replace(/\b(created_at|expires) INTEGER/g,'$1 BIGINT'));return ready;},
      lock:text=>text+' FOR UPDATE',
      prepare(text){return {async run(...args){const r=await query(text,args);return {changes:r.rowCount}},async get(...args){return (await query(text,args)).rows[0]},async all(...args){return (await query(text,args)).rows}}},
      async transaction(fn){await ready;const client=await pool.connect();try{await client.query('BEGIN');const value=await context.run(client,fn);await client.query('COMMIT');return value;}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}},
      close:()=>pool.end()
    };
  }
  if(process.env.RENDER&&!process.env.DATA_DIR)throw new Error('무료 데이터베이스 DATABASE_URL을 먼저 연결해주세요.');
  const fs=require('fs'),path=require('path'),{DatabaseSync}=require('node:sqlite');
  const dir=process.env.DATA_DIR||path.join(__dirname,'data');fs.mkdirSync(dir,{recursive:true,mode:0o700});
  const file=path.join(dir,'maumset.sqlite'),db=new DatabaseSync(file);fs.chmodSync(file,0o600);
  async function call(fn){await ready;if(!context.getStore())await serial;return fn();}
  return {kind:'sqlite',
    init(schema){db.exec('PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;'+schema);return ready;},
    lock:text=>text,
    prepare(text){return {run:(...args)=>call(()=>db.prepare(text).run(...args)),get:(...args)=>call(()=>db.prepare(text).get(...args)),all:(...args)=>call(()=>db.prepare(text).all(...args))}},
    transaction(fn){const result=serial.then(()=>context.run(true,async()=>{db.exec('BEGIN IMMEDIATE');try{const value=await fn();db.exec('COMMIT');return value;}catch(e){db.exec('ROLLBACK');throw e;}}));serial=result.catch(()=>{});return result;},
    async close(){await serial;db.close();}
  };
};

return module.exports;
})();
const createAccounts = (() => {
const module={exports:{}};
'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);
const SESSION_MS = 30 * 24 * 60 * 60 * 1000;
const COOKIE = 'maumset_session';
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const failure = (message, status=400) => Object.assign(new Error(message),{status});

module.exports = function createAccounts({onRevoke=()=>{}}={}) {
  const db=createStorage();
  const ready=db.init(`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
      nickname TEXT NOT NULL, gender TEXT NOT NULL CHECK(gender IN ('남','여')), age INTEGER NOT NULL CHECK(age BETWEEN 1 AND 120), created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, expires INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scores (
      account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
      weekly INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0, sessions INTEGER NOT NULL DEFAULT 0, week_key TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invitations (
      token_hash TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      expires INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'waiting'
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      amount INTEGER NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reward_tickets (
      token_hash TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      recipients TEXT NOT NULL, expires INTEGER NOT NULL, result TEXT
    );`);
  const attempts=new Map();let busy=0;
  function profile(r){return r?{id:r.id,username:r.username,nickname:r.nickname,gender:r.gender,age:r.age}:null;}
  async function session(req){
    const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='));
    if(!raw)return null;const token=raw.slice(COOKIE.length+1);if(!/^[a-f0-9]{64}$/.test(token))return null;
    const tokenHash=hash(token);
    const row=await db.prepare('SELECT a.*, s.expires FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=? AND s.expires>?').get(tokenHash,Date.now());
    return row?{user:profile(row),tokenHash}:null;
  }
  async function requireUser(req){const s=await session(req);if(!s)throw failure('로그인이 필요합니다.',401);return s;}
  function sameOrigin(req){
    const origin=req.headers.origin;
    if(!origin)return false;
    try{return new URL(origin).host===req.headers.host && ['http:','https:'].includes(new URL(origin).protocol);}catch{return false;}
  }
  function cookie(req,res,token,maxAge=SESSION_MS/1000){
    const secure=req.socket.encrypted || process.env.RENDER || process.env.NODE_ENV==='production';
    res.setHeader('Set-Cookie',`${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure?'; Secure':''}`);
  }
  function json(res,status,data){res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});res.end(JSON.stringify(data));}
  async function body(req){let raw='';for await(const chunk of req){raw+=chunk;if(Buffer.byteLength(raw)>8192)throw failure('입력 내용이 너무 깁니다.');}try{return JSON.parse(raw);}catch{throw failure('입력 내용을 확인해주세요.');}}
  function rateLimit(req,username){
    const now=Date.now();for(const [key,v] of attempts)if(v.until<now)attempts.delete(key);
    for(const [key,max] of [[`ip:${req.socket.remoteAddress}`,60],[`user:${String(username||'').toLowerCase().slice(0,32)}`,15]]){
      const r=attempts.get(key)||{count:0,until:now+15*60000};r.count++;attempts.set(key,r);
      if(r.count>max)throw failure('시도가 너무 많습니다. 15분 후 다시 시도해주세요.',429);
    }
  }
  function credentials(m){
    const username=String(m.username||'').trim().toLowerCase(),password=m.password;
    if(!/^[a-z0-9_]{4,32}$/.test(username))throw failure('아이디는 영문·숫자·밑줄 4~32자로 입력해주세요.');
    if(typeof password!=='string'||password.length<8||password.length>128)throw failure('비밀번호는 8~128자로 입력해주세요.');
    return {username,password};
  }
  async function derive(password,salt){
    if(busy>=4)throw failure('잠시 후 다시 시도해주세요.',429);busy++;
    try{return await scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:64*1024*1024});}finally{busy--;}
  }
  const dummySalt=crypto.randomBytes(16).toString('hex');
  async function verify(password,row){const key=await derive(password,row?row.salt:dummySalt);return !!row&&crypto.timingSafeEqual(key,Buffer.from(row.password_hash,'hex'));}
  async function newSession(req,res,id){
    const token=crypto.randomBytes(32).toString('hex');
    await db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());
    await db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hash(token),id,Date.now()+SESSION_MS);
    cookie(req,res,token);
  }
  async function handle(req,res){
    const route=req.url.split('?')[0];if(!['/api/me','/api/register','/api/login','/api/logout','/api/account','/api/notifications','/api/notifications/ack','/api/invites','/api/invites/info'].includes(route))return false;
    try{
      if(route==='/api/notifications'&&req.method==='GET'){const auth=await requireUser(req);json(res,200,{notifications:await notifications(auth.user.id)});return true;}
      if(route==='/api/me'&&req.method==='GET'){
        const s=await session(req);
        if(s){await db.prepare('UPDATE sessions SET expires=? WHERE token_hash=?').run(Date.now()+SESSION_MS,s.tokenHash);const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'=')).slice(COOKIE.length+1);cookie(req,res,raw);}
        json(res,200,{user:s?.user||null});return true;
      }
      if(req.method!=='POST'){json(res,405,{error:'지원하지 않는 요청입니다.'});return true;}
      if(!sameOrigin(req))throw failure('요청 출처를 확인할 수 없습니다.',403);
      const m=await body(req);
      if(route==='/api/invites'){
        const auth=await requireUser(req);rateLimit(req,auth.user.username);
        await db.prepare('DELETE FROM invitations WHERE expires<?').run(Date.now());
        const token=crypto.randomBytes(24).toString('hex'),expires=Date.now()+24*3600000;
        await db.prepare('INSERT INTO invitations VALUES(?,?,?,?)').run(hash(token),auth.user.id,expires,'waiting');
        json(res,201,{token,expires});
      }else if(route==='/api/invites/info'){
        await requireUser(req);const invite=await invitation(m.token);if(!invite)throw failure('초대 링크가 만료되었거나 닫혔습니다.',404);
        json(res,200,{expires:invite.expires,state:invite.state});
      }else if(route==='/api/notifications/ack'){const auth=await requireUser(req);if(typeof m.id!=='string'||m.id.length>64)throw failure('알림을 확인할 수 없습니다.');await db.prepare('DELETE FROM notifications WHERE id=? AND account_id=?').run(m.id,auth.user.id);json(res,200,{ok:true});}
      else if(route==='/api/register'){
        const {username,password}=credentials(m);rateLimit(req,username);
        const nickname=String(m.nickname||'').trim(),gender=m.gender,age=Number(m.age);
        if(!nickname||nickname.length>20)throw failure('닉네임은 1~20자로 입력해주세요.');
        if(!['남','여'].includes(gender)||!Number.isInteger(age)||age<1||age>120)throw failure('성별과 나이를 확인해주세요.');
        if(await db.prepare('SELECT id FROM accounts WHERE username=?').get(username))throw failure('이미 사용 중인 아이디입니다.',409);
        const salt=crypto.randomBytes(16).toString('hex'),key=await derive(password,salt),id=crypto.randomUUID();
        try{await db.prepare('INSERT INTO accounts VALUES(?,?,?,?,?,?,?,?)').run(id,username,key.toString('hex'),salt,nickname,gender,age,Date.now());}catch(e){if((e.code?.includes('CONSTRAINT')||e.code==='23505'))throw failure('이미 사용 중인 아이디입니다.',409);throw e;}
        await newSession(req,res,id);json(res,201,{user:profile(await db.prepare('SELECT * FROM accounts WHERE id=?').get(id))});
      }else if(route==='/api/login'){
        const {username,password}=credentials(m);rateLimit(req,username);
        const row=await db.prepare('SELECT * FROM accounts WHERE username=?').get(username);
        if(!await verify(password,row))throw failure('아이디 또는 비밀번호가 맞지 않습니다.',401);
        const old=await session(req);if(old)await db.prepare('DELETE FROM sessions WHERE token_hash=?').run(old.tokenHash);
        await newSession(req,res,row.id);json(res,200,{user:profile(row)});
      }else if(route==='/api/logout'){
        const s=await session(req);if(s){await db.prepare('DELETE FROM sessions WHERE token_hash=?').run(s.tokenHash);await onRevoke(s.user.id,s.tokenHash);}
        cookie(req,res,'',0);json(res,200,{ok:true});
      }else if(route==='/api/account'){
        const s=await requireUser(req);rateLimit(req,s.user.username);
        if(typeof m.password!=='string'||m.password.length>128)throw failure('비밀번호를 입력해주세요.');
        const row=await db.prepare('SELECT * FROM accounts WHERE id=?').get(s.user.id);
        if(!await verify(m.password,row))throw failure('비밀번호가 맞지 않습니다.',401);
        await db.transaction(async()=>{
          for(const ticket of await db.prepare(db.lock('SELECT * FROM reward_tickets WHERE owner_id<>?')).all(s.user.id)){
            const recipients=JSON.parse(ticket.recipients).filter(r=>r.accountId!==s.user.id);
            const result=ticket.result?JSON.parse(ticket.result):null;
            if(result)result.recipients=result.recipients.filter(r=>r.accountId!==s.user.id);
            await db.prepare('UPDATE reward_tickets SET recipients=?,result=? WHERE token_hash=?').run(JSON.stringify(recipients),result?JSON.stringify(result):null,ticket.token_hash);
          }
          await db.prepare('DELETE FROM accounts WHERE id=?').run(s.user.id);
        });
        await onRevoke(s.user.id);cookie(req,res,'',0);json(res,200,{ok:true});
      }
    }catch(e){json(res,e.status||500,{error:e.status?e.message:'요청을 처리하지 못했습니다. 다시 시도해주세요.'});}
    return true;
  }
  async function createTicket(token,ownerId,recipients){
    await db.prepare('DELETE FROM reward_tickets WHERE expires<?').run(Date.now());
    await db.prepare('INSERT INTO reward_tickets VALUES(?,?,?,?,NULL)').run(hash(token),ownerId,JSON.stringify(recipients),Date.now()+24*3600000);
  }
  function publicResult(result){return {...result,recipients:result.recipients.map(({nickname,amount})=>({nickname,amount}))};}
  async function recordReward(token,amount,ownerId,weekKey){
    if(typeof token!=='string')throw failure('보상 정보가 없습니다.');
    if(![0,1000,2000,3000].includes(amount))throw failure('올바른 보상 금액을 선택해주세요.');
    return db.transaction(async()=>{
      const ticket=await db.prepare(db.lock('SELECT * FROM reward_tickets WHERE token_hash=? AND owner_id=? AND expires>?')).get(hash(token),ownerId,Date.now());
      if(!ticket)throw failure('보상 기록 시간이 만료되었거나 권한이 없습니다.');
      if(ticket.result)return publicResult(JSON.parse(ticket.result));
      const each=Math.floor(amount/3),recipients=[];
      for(const m of JSON.parse(ticket.recipients)){
        const account=await db.prepare('SELECT nickname FROM accounts WHERE id=?').get(m.accountId);if(!account)continue;
        await db.prepare(`INSERT INTO scores VALUES(?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
          weekly=CASE WHEN scores.week_key=excluded.week_key THEN scores.weekly+excluded.weekly ELSE excluded.weekly END,
          total=scores.total+excluded.total,sessions=scores.sessions+1,week_key=excluded.week_key`).run(m.accountId,each,each,1,weekKey);
        recipients.push({accountId:m.accountId,nickname:account.nickname,amount:each});
        if(each>0)await db.prepare('INSERT INTO notifications VALUES(?,?,?,?)').run(crypto.randomUUID(),m.accountId,each,Date.now());
      }
      const result={amount,split:[each,each,amount-2*each],recipients};
      await db.prepare('UPDATE reward_tickets SET result=? WHERE token_hash=?').run(JSON.stringify(result),hash(token));return publicResult(result);
    });
  }
  async function rankings(type,weekKey){
    const rows=type==='weekly'?await db.prepare(`SELECT a.nickname,s.weekly AS amount,s.sessions FROM scores s JOIN accounts a ON a.id=s.account_id WHERE s.week_key=? AND s.weekly>0 ORDER BY s.weekly DESC,a.id LIMIT 20`).all(weekKey):await db.prepare(`SELECT a.nickname,s.total AS amount,s.sessions FROM scores s JOIN accounts a ON a.id=s.account_id ORDER BY s.total DESC,a.id LIMIT 20`).all();
    return rows.map((r,i)=>({rank:i+1,...r}));
  }
  async function notifications(accountId){return await db.prepare('SELECT id,amount,created_at AS "createdAt" FROM notifications WHERE account_id=? ORDER BY created_at,id LIMIT 100').all(accountId);}
  async function invitation(token){
    if(typeof token!=='string'||!/^[a-f0-9]{48}$/.test(token))return null;
    return await db.prepare("SELECT token_hash AS key,owner_id AS \"ownerId\",expires,state FROM invitations WHERE token_hash=? AND expires>?").get(hash(token),Date.now())||null;
  }
  async function matchInvitation(key){return (await db.prepare("UPDATE invitations SET state='matched' WHERE token_hash=? AND state='waiting' AND expires>?").run(key,Date.now())).changes===1;}
  return {ready,invitation,matchInvitation,notifications,handle,session,requireUser,sameOrigin,createTicket,recordReward,rankings,close:()=>db.close()};
};

return module.exports;
})();
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const rooms = new Map();
const queues = { 하나: [], 둘: [] };
const privateQueues = new Map();
let actions=Promise.resolve();
function schedule(fn){const next=actions.then(fn);actions=next.catch(()=>{});return next;}
const users = new Map();
const rewardTickets = new Map();
const crypto = require('crypto');
const ROOM_DURATION_MS = Number(process.env.ROOM_DURATION_MS) > 0 ? Number(process.env.ROOM_DURATION_MS) : 300000;
const accounts = createAccounts({onRevoke(accountId,tokenHash){return schedule(async()=>{
  if(!tokenHash)for(const [key,queue] of privateQueues)if(queue.ownerId===accountId){
    for(const member of [...queue.하나,...queue.둘]){member.queueKey=null;send(member.ws,'inviteClosed',{message:'방장이 탈퇴하여 초대방이 닫혔습니다.'});}privateQueues.delete(key);
  }
  for(const user of users.values())if(user.accountId===accountId&&(!tokenHash||user.sessionHash===tokenHash)){
    removeFromQueue(user);const room=rooms.get(user.roomId);if(room&&!room.completed)endRoom(room,'참여자가 로그아웃하여 대화가 종료되었습니다.');
    send(user.ws,'authExpired');user.ws.close(1008,'Authentication ended');
  }
});}});

function id() { return Math.random().toString(36).slice(2, 10) + Date.now().toString(36); }
function send(ws, type, data={}) { if (ws.readyState === 1) ws.send(JSON.stringify({type, ...data})); }
function broadcast(room, type, data={}) { room.members.forEach(m => send(m.ws, type, data)); }
function publicMember(m) { return { id:m.id, role:m.role, nickname:m.nickname }; }
function roomState(room) { return { roomId:room.id, members:room.members.map(publicMember), seconds: Math.max(0, Math.ceil((room.endsAt-Date.now())/1000)) }; }

function getLocalUrls() {
  const out=[]; let nets; try { nets=os.networkInterfaces(); } catch { return out; }
  for (const list of Object.values(nets)) for (const n of list || []) if (n.family === 'IPv4' && !n.internal) out.push(`http://${n.address}:${PORT}`);
  return out;
}

function makeRoom(one, two, three) {
  const room={id:id(), members:[one,two,three], ownerId:one.accountId, recipients:[two,three].map(m=>({accountId:m.accountId})), endsAt:Date.now()+ROOM_DURATION_MS, ended:false};
  rooms.set(room.id, room);
  for (const m of room.members) { m.roomId=room.id; users.set(m.id,m); }
  room.members.forEach(m => send(m.ws,'matched',{room:roomState(room), self:m.id}));
  broadcast(room,'system',{text:'세 명이 모였습니다. 5분 대화를 시작합니다.'});
  room.timer=setTimeout(()=>schedule(()=>finishRoom(room)).catch(()=>endRoom(room,'보상 준비 중 오류가 발생했습니다.')),ROOM_DURATION_MS);
  return room;
}
function queueCounts(queue){return {하나:queue.하나.length,둘:queue.둘.length};}
function updateQueue(queue,isPrivate=false){for(const member of [...queue.하나,...queue.둘])send(member.ws,'queued',{role:member.role,private:isPrivate,counts:queueCounts(queue)});}
async function tryMatch(queue=queues,key=null) {
  while(queue.하나.length&&queue.둘.length>=2){
    if(key&&!await accounts.matchInvitation(key)){for(const m of [...queue.하나,...queue.둘]){m.queueKey=null;send(m.ws,'inviteClosed',{message:'초대 링크가 만료되었거나 이미 사용되었습니다.'});}privateQueues.delete(key);return;}
    const one=queue.하나.shift(),two=queue.둘.shift(),three=queue.둘.shift();
    for(const m of [one,two,three])m.queueKey=null;
    one.role='하나';two.role='둘';three.role='셋';makeRoom(one,two,three);
    if(key){privateQueues.delete(key);break;}
  }
  updateQueue(queue,!!key);
}
function removeFromQueue(user){
  const key=user.queueKey,queue=key?privateQueues.get(key):queues;
  if(queue){for(const role of ['하나','둘']){const i=queue[role].findIndex(x=>x.id===user.id);if(i>=0)queue[role].splice(i,1);}updateQueue(queue,!!key);if(key&&!queue.하나.length&&!queue.둘.length)privateQueues.delete(key);}
  user.queueKey=null;
}
async function finishRoom(room) {
  if (!room || room.ended || room.completed) return;
  room.completed=true; clearTimeout(room.timer);
  // Supporters can rejoin immediately. Only 마음하나 remains attached to submit reward.
  room.members.filter(m => m.role !== '하나').forEach(m => { if (m.roomId === room.id) m.roomId = null; });
  room.cleanupTimer=setTimeout(()=>{ rooms.delete(room.id); room.members.forEach(m=>{if(m.roomId===room.id)m.roomId=null;}); },600000);
  const token=crypto.randomBytes(32).toString('hex');
  await accounts.createTicket(token,room.ownerId,room.recipients);
  for(const [key,ticket] of rewardTickets)if(ticket.expires<Date.now())rewardTickets.delete(key);
  rewardTickets.set(token,{room,expires:Date.now()+24*3600000});
  room.members.forEach(m=>send(m.ws,'completed',{message:'5분 대화가 완료되었습니다.',...(m.role==='하나'?{rewardToken:token}:{})}));
}
function endRoom(room, reason) {
  if (!room || room.ended) return;
  room.ended=true; clearTimeout(room.timer); clearTimeout(room.cleanupTimer);
  broadcast(room,'roomEnded',{reason});
  room.members.forEach(m=>{m.roomId=null; users.set(m.id,m);});
  rooms.delete(room.id);
}
function weekKey() {
  const d=new Date();
  // Korea timezone for the weekly board, Monday start.
  const kst=new Date(d.getTime()+9*3600000);
  const day=kst.getUTCDay();
  kst.setUTCDate(kst.getUTCDate()-(day===0?6:day-1));
  return kst.toISOString().slice(0,10);
}
function rankingsPayload(type) { return accounts.rankings(type,weekKey()); }
async function recordReward(token,value,accountId) {
  const result=await accounts.recordReward(token,Number(value),accountId,weekKey());
  const ticket=rewardTickets.get(token);
  if(ticket){const room=ticket.room;room.ended=true;clearTimeout(room.timer);clearTimeout(room.cleanupTimer);
    room.members.forEach(m=>{if(m.roomId===room.id)m.roomId=null;});rooms.delete(room.id);rewardTickets.delete(token);}
  wss.clients.forEach(client=>send(client,'rankingChanged'));
  for(const user of users.values())if(await accounts.session(user.request)&&(await accounts.notifications(user.accountId)).length)send(user.ws,'notificationsChanged');
  return result;
}

const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');
  if(await accounts.handle(req,res))return;
  if(req.url.split('?')[0]==='/api/rankings' && req.method==='GET') {
    const type=new URL(req.url,'http://localhost').searchParams.get('type')==='total'?'total':'weekly';
    res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});
    return res.end(JSON.stringify({type,rows:await rankingsPayload(type)}));
  }
  if(req.url==='/api/reward' && req.method==='POST') {
    let auth;try{if(!accounts.sameOrigin(req))throw new Error('요청 출처를 확인할 수 없습니다.');auth=await accounts.requireUser(req);}catch(e){res.writeHead(e.status||403,{'content-type':'application/json; charset=utf-8'});res.end(JSON.stringify({error:e.message}));return;}
    let body=''; req.on('data',chunk=>{body+=chunk; if(body.length>4096)req.destroy();});
    req.on('end',async()=>{try { const msg=JSON.parse(body); const result=await recordReward(msg.rewardToken,msg.amount,auth.user.id);
      res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'});res.end(JSON.stringify(result));
    } catch(e) {res.writeHead(400,{'content-type':'application/json; charset=utf-8'});res.end(JSON.stringify({error:e.message}));}});return;
  }
  let file=req.url.split('?')[0]; if(file==='/') file='/index.html';
  if(file==='/api/health'){res.writeHead(200,{'content-type':'application/json'}); return res.end(JSON.stringify({ok:true}));}
  const p=path.join(__dirname,'public',path.normalize(file));
  if(!p.startsWith(path.join(__dirname,'public'))) {res.writeHead(403);return res.end('Forbidden');}
  fs.readFile(p,(err,data)=>{if(err){res.writeHead(404);return res.end('Not found');} const ext=path.extname(p); const ct=ext==='.html'?'text/html; charset=utf-8':ext==='.js'?'text/javascript':ext==='.css'?'text/css':'application/octet-stream'; res.writeHead(200,{'content-type':ct,'cache-control':'no-store'});res.end(data);});
});
const wss=new WebSocketServer({server,maxPayload:8192,verifyClient:({req},done)=>{if(!accounts.sameOrigin(req)){done(false,403);return;}accounts.session(req).then(auth=>{req.maumsetAuth=auth;done(!!auth,auth?undefined:401);}).catch(()=>done(false,503));}});
wss.on('connection',(ws,req)=>{
  const auth=req.maumsetAuth;if(!auth){ws.close(1008);return;}
  const user={id:id(),ws,request:req,role:null,nickname:auth.user.nickname,accountId:auth.user.id,sessionHash:auth.tokenHash}; users.set(user.id,user);
  send(ws,'hello',{id:user.id});
  ws.on('message',(raw)=>{schedule(async()=>{
    const current=await accounts.session(req);if(!current){send(ws,'authExpired');ws.close(1008);return;}
    let msg; try{msg=JSON.parse(raw.toString())}catch{return}
    if(!msg||typeof msg!=='object')return;
    if(msg.type==='joinQueue'){
      if(user.roomId){send(ws,'error',{message:'이미 채팅방에 참여 중입니다.'});return;} if(queues.하나.includes(user)||queues.둘.includes(user)){send(ws,'error',{message:'이미 대기방에서 매칭을 기다리고 있습니다.'});return;}
      if([...users.values()].some(u=>u!==user&&u.accountId===user.accountId&&(u.roomId||u.queueKey||queues.하나.includes(u)||queues.둘.includes(u)))){send(ws,'error',{message:'다른 창에서 이미 참여 중입니다.'});return;}
      user.role=msg.role==='하나'?'하나':'둘';user.nickname=current.user.nickname;
      const queue=queues,key=null;
      user.queueKey=key;queue[user.role].push(user);updateQueue(queue,!!key);await tryMatch(queue,key);
    } else if(msg.type==='cancelQueue') { removeFromQueue(user); send(ws,'queueCancelled'); }
    else if(msg.type==='chat') { const room=rooms.get(user.roomId); if(!room||room.ended||room.completed)return; const text=String(msg.text||'').trim().slice(0,1000); if(!text)return; broadcast(room,'chat',{message:{id:id(),who:user.role,nickname:user.nickname,text,at:Date.now()}}); }
    else if(msg.type==='leaveRoom') { const room=rooms.get(user.roomId); if(room) endRoom(room,`${user.role==='하나'?'마음하나':'참여자'}가 나가 채팅방이 종료되었습니다.`); }
    else if(msg.type==='reward') { try { const result=await recordReward(msg.rewardToken,msg.amount,user.accountId); send(ws,'rewardRecorded',result); } catch(e) { send(ws,'error',{message:e.message}); } }
    else if(msg.type==='ranking') send(ws,'ranking',{rankingType:msg.rankingType==='total'?'total':'weekly',rows:await rankingsPayload(msg.rankingType)});
  }).catch(()=>send(ws,'error',{message:'요청을 처리하지 못했습니다. 다시 시도해주세요.'}));});
  ws.on('close',()=>{schedule(async()=>{ removeFromQueue(user); const room=rooms.get(user.roomId); if(room && !room.ended && !room.completed) endRoom(room,'한 명의 연결이 끊어져 채팅방이 종료되었습니다.'); users.delete(user.id); }).catch(()=>{});});
});
if(require.main===module)accounts.ready.then(()=>server.listen(PORT,()=>{console.log('\n마음셋 서버가 시작되었습니다.');console.log(`PC: http://localhost:${PORT}`);for(const u of getLocalUrls()) console.log(`휴대폰: ${u}`);console.log('인터넷에 서버를 배포하면 Wi-Fi 없이 휴대폰 모바일 데이터로 접속할 수 있습니다.\n');})).catch(()=>{console.error('데이터베이스 연결 설정을 확인해주세요.');process.exitCode=1;});

server.on('close',()=>{for(const room of rooms.values()){clearTimeout(room.timer);clearTimeout(room.cleanupTimer);}rooms.clear();rewardTickets.clear();privateQueues.clear();});
module.exports={server,wss,accounts,idle:()=>actions};
