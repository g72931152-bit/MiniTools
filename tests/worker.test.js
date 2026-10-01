import test from 'node:test';
import assert from 'node:assert/strict';
const worker = (await import('../src/worker.js')).default;

class MockStmt {
  constructor(db, sql) { this.db = db; this.sql = sql; this.params = []; }
  bind(...p) { this.params = p; return this; }
  async first() { return this.db.first(this.sql, this.params); }
  async all() { return { results: this.db.all(this.sql, this.params) }; }
  async run() { return { meta: { changes: this.db.run(this.sql, this.params) } }; }
}
class MockDB {
  constructor() { this.capsules = new Map(); this.sessions = new Map(); this.approvals = []; this.audit = []; }
  prepare(sql) { return new MockStmt(this, sql); }
  async batch(stmts) { for (const s of stmts) await s.run(); }
  first(sql, p) {
    if (sql.startsWith('SELECT * FROM capsules WHERE id=? AND access_hash=?')) return [...this.capsules.values()].find(x => x.id === p[0] && x.access_hash === p[1]) || null;
    if (sql.startsWith('SELECT owner_hash FROM capsules WHERE id=?')) { const c=this.capsules.get(p[0]); return c ? {owner_hash:c.owner_hash} : null; }
    if (sql.startsWith('SELECT * FROM capsules WHERE id=?')) return this.capsules.get(p[0]) || null;
    if (sql.startsWith('SELECT * FROM sessions WHERE id=?')) return this.sessions.get(p[0]) || null;
    if (sql.startsWith('SELECT s.*, c.status')) { const s = this.sessions.get(p[0]); const c = this.capsules.get(p[1]); return s && c ? {...s, capsule_status:c.status, expires_at:c.expires_at, one_time:c.one_time, consumed_at:c.consumed_at} : null; }
    if (sql.includes('SELECT event_hash FROM audit_events')) { const e = [...this.audit].filter(x=>x.capsule_id===p[0]).at(-1); return e ? {event_hash:e.event_hash}:null; }
    return null;
  }
  all(sql,p) {
    if (sql.includes('FROM sessions WHERE capsule_id')) return [...this.sessions.values()].filter(x=>x.capsule_id===p[0]);
    if (sql.includes('FROM audit_events WHERE capsule_id')) return [...this.audit].filter(x=>x.capsule_id===p[0]);
    return [];
  }
  run(sql,p) {
    if (sql.startsWith('INSERT INTO capsules')) { this.capsules.set(p[0],{id:p[0],access_hash:p[1],owner_hash:p[2],envelope:p[3],payload_ciphertext:p[4],metadata_ciphertext:p[5],mode:p[6],status:p[7],one_time:p[8],consumed_at:null,expires_at:p[9],created_at:p[10],updated_at:p[11]}); return 1; }
    if (sql.startsWith('INSERT INTO sessions')) { this.sessions.set(p[0],{id:p[0],capsule_id:p[1],state:p[2],device:p[3],os:p[4],browser:p[5],region:p[6],created_at:p[7],updated_at:p[8]}); return 1; }
    if (sql.startsWith('INSERT INTO approvals')) { this.approvals.push({capsule_id:p[0],session_id:p[1],decision:p[2],created_at:p[3]}); return 1; }
    if (sql.startsWith('INSERT INTO audit_events')) { this.audit.push({capsule_id:p[0],event_type:p[1],session_id:p[2],detail:p[3],event_hash:p[4],previous_hash:p[5],created_at:p[6]}); return 1; }
    if (sql.startsWith('UPDATE approvals SET decision')) { const a=this.approvals.find(x=>x.session_id===p[2]); if(a){a.decision=p[0];a.decided_at=p[1];return 1;} return 0; }
    if (sql.startsWith('UPDATE sessions SET state')) { let n=0; for(const s of this.sessions.values()) if((sql.includes('WHERE capsule_id')?s.capsule_id===p[1]:s.id===p[2])){s.state=p[0];s.updated_at=p[1];n++;} return n; }
    if (sql.startsWith('UPDATE capsules SET consumed_at')) { const c=this.capsules.get(p[2]); if(c && c.one_time===1 && !c.consumed_at && c.status==='active'){c.consumed_at=p[0];c.updated_at=p[1];return 1;} return 0; }
    if (sql.startsWith('UPDATE capsules SET status')) { const c=this.capsules.get(p[1]); if(c && (!sql.includes("AND status='active'") || c.status==='active')){c.status=p[0];c.updated_at=p[0]===undefined?p[0]:p[0];return 1;} return 0; }
    return 0;
  }
}

function req(path, body, method='POST') { return new Request('https://cipher.test'+path,{method,headers:{'content-type':'application/json','origin':'https://cipher.test'},body:body?JSON.stringify(body):undefined}); }

test('worker creates capsule and does not need plaintext field', async ()=>{
  const DB=new MockDB(); const env={DB,ASSETS:{fetch:async()=>new Response('asset')}};
  const res=await worker.fetch(req('/api/capsules',{envelope:'E',payloadCiphertext:'P',metadataCiphertext:'M',accessHash:'a'.repeat(64),ownerHash:'c'.repeat(64),mode:'standard'}),env);
  assert.equal(res.status,200); const body=await res.json(); assert.ok(body.id); assert.equal(DB.capsules.size,1);
});

test('owner authentication gates decisions and approved session can receive ciphertext', async ()=>{
  const cryptoMod = await import('../public/js/crypto.js');
  const DB=new MockDB(); const env={DB,ASSETS:{fetch:async()=>new Response('asset')}};
  const pack=await cryptoMod.createCapsulePackage('Server never sees this plaintext', {mode:'approval', capsuleId:'A1B2C3D4E5F60708'});
  const ownerAttempt=await worker.fetch(req('/api/capsules',{envelope:JSON.stringify(pack.envelope),payloadCiphertext:JSON.stringify(pack.messageRecord),metadataCiphertext:JSON.stringify(pack.metadataRecord),accessHash:pack.accessHash,ownerHash:pack.ownerHash,capsuleId:'A1B2C3D4E5F60708',mode:'approval'}),env);
  assert.equal(ownerAttempt.status,200);
  const denied=await worker.fetch(req('/api/access/decision',{capsuleId:'A1B2C3D4E5F60708',sessionId:'missing',ownerHash:'0'.repeat(64),decision:'approved'}),env);
  assert.equal(denied.status,403);
  const access=await worker.fetch(req('/api/access/request',{capsuleId:'A1B2C3D4E5F60708',accessHash:pack.accessHash}),env);
  assert.equal(access.status,200); const sessionId=(await access.json()).sessionId;
  const approved=await worker.fetch(req('/api/access/decision',{capsuleId:'A1B2C3D4E5F60708',sessionId,ownerHash:pack.ownerHash,decision:'approved'}),env);
  assert.equal(approved.status,200);
  const opened=await worker.fetch(req('/api/capsules/open',{capsuleId:'A1B2C3D4E5F60708',sessionId}),env);
  assert.equal(opened.status,200); const body=await opened.json();
  assert.equal(body.capsule.id,'A1B2C3D4E5F60708');
  assert.ok(body.capsule.payloadCiphertext);
});

test('one-time capsule can be consumed only once', async ()=>{
  const cryptoMod = await import('../public/js/crypto.js');
  const DB=new MockDB(); const env={DB,ASSETS:{fetch:async()=>new Response('asset')}};
  const pack=await cryptoMod.createCapsulePackage('once', {mode:'one-time', capsuleId:'0A0B0C0D0E0F1011'});
  await worker.fetch(req('/api/capsules',{envelope:JSON.stringify(pack.envelope),payloadCiphertext:JSON.stringify(pack.messageRecord),metadataCiphertext:JSON.stringify(pack.metadataRecord),accessHash:pack.accessHash,ownerHash:pack.ownerHash,capsuleId:'0A0B0C0D0E0F1011',mode:'one-time'}),env);
  const access=await worker.fetch(req('/api/access/request',{capsuleId:'0A0B0C0D0E0F1011',accessHash:pack.accessHash}),env);
  const sessionId=(await access.json()).sessionId;
  const first=await worker.fetch(req('/api/capsules/open',{capsuleId:'0A0B0C0D0E0F1011',sessionId}),env);
  assert.equal(first.status,200);
  const second=await worker.fetch(req('/api/capsules/open',{capsuleId:'0A0B0C0D0E0F1011',sessionId}),env);
  assert.equal(second.status,410);
});

test('request access creates pending session', async ()=>{
  const DB=new MockDB(); const env={DB,ASSETS:{fetch:async()=>new Response('asset')}};
  await worker.fetch(req('/api/capsules',{envelope:'E',payloadCiphertext:'P',metadataCiphertext:'M',accessHash:'b'.repeat(64),ownerHash:'d'.repeat(64),mode:'approval'}),env);
  const id=[...DB.capsules.keys()][0];
  const res=await worker.fetch(req('/api/access/request',{capsuleId:id,accessHash:'b'.repeat(64)}),env);
  assert.equal(res.status,200); const body=await res.json(); assert.equal(body.state,'pending'); assert.equal(DB.sessions.size,1);
});
