const JSON_HEADERS = { "content-type": "application/json; charset=UTF-8" };
const MAX_BODY = 600_000;
const SESSION_TTL_MS = 15 * 60 * 1000;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, "cache-control": "no-store", ...extra }
  });
}

function bad(message, status = 400, code = "BAD_REQUEST") {
  return json({ error: { code, message } }, status);
}

function now() { return Date.now(); }

function randomId(bytes = 12) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(x => x.toString(16).padStart(2, "0")).join("");
}

function cleanString(value, max = 10000) {
  if (typeof value !== "string") return null;
  const v = value.trim();
  return v.length && v.length <= max ? v : null;
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function readJson(request) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len > MAX_BODY) throw new Error("PAYLOAD_TOO_LARGE");
  const text = await request.text();
  if (text.length > MAX_BODY) throw new Error("PAYLOAD_TOO_LARGE");
  try { return JSON.parse(text); } catch { throw new Error("INVALID_JSON"); }
}

function clientContext(request) {
  const cf = request.cf || {};
  const ua = request.headers.get("user-agent") || "Unknown";
  const browser = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "Unknown";
  const region = typeof cf.country === "string" ? cf.country : "Unknown";
  return { device: /Mobile|Android|iPhone|iPad/.test(ua) ? "Mobile" : "Desktop", os, browser, region };
}

function originAllowed(request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  const url = new URL(request.url);
  return origin === url.origin;
}

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("content-security-policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", "geolocation=(), microphone=(), camera=()");
  headers.set("access-control-allow-origin", "same-origin");
  headers.set("access-control-allow-headers", "content-type");
  headers.set("access-control-allow-methods", "GET,POST,OPTIONS");
  return new Response(response.body, { status: response.status, headers });
}

async function audit(db, capsuleId, type, detail, sessionId = null) {
  const last = await db.prepare("SELECT event_hash FROM audit_events WHERE capsule_id = ? ORDER BY id DESC LIMIT 1").bind(capsuleId).first();
  const ts = now();
  const previous = last?.event_hash || "GENESIS";
  const material = `${capsuleId}|${type}|${detail}|${sessionId || ""}|${ts}|${previous}`;
  const hash = await sha256Hex(material);
  await db.prepare(
    "INSERT INTO audit_events (capsule_id,event_type,session_id,detail,event_hash,previous_hash,created_at) VALUES (?,?,?,?,?,?,?)"
  ).bind(capsuleId, type, sessionId, detail, hash, previous, ts).run();
}

async function capsuleIsOpenable(db, capsule) {
  if (!capsule) return { ok: false, status: 404, code: "NOT_FOUND", message: "Capsule not found." };
  if (capsule.status !== "active") return { ok: false, status: 410, code: "LOCKED", message: "Capsule is locked." };
  if (capsule.expires_at && capsule.expires_at <= now()) {
    await db.prepare("UPDATE capsules SET status='expired', updated_at=? WHERE id=? AND status='active'").bind(now(), capsule.id).run();
    return { ok: false, status: 410, code: "EXPIRED", message: "Capsule has expired." };
  }
  if (capsule.one_time && capsule.consumed_at) return { ok: false, status: 410, code: "CONSUMED", message: "One-time capsule has already been consumed." };
  return { ok: true };
}

async function createCapsule(request, env) {
  const body = await readJson(request);
  const envelope = cleanString(body.envelope, 180000);
  const payloadCiphertext = cleanString(body.payloadCiphertext, 500000);
  const metadataCiphertext = cleanString(body.metadataCiphertext, 180000);
  const accessHash = cleanString(body.accessHash, 128);
  const ownerHash = cleanString(body.ownerHash, 128);
  const mode = cleanString(body.mode, 32);
  const requestedId = cleanString(body.capsuleId, 32);
  if (!envelope || !payloadCiphertext || !metadataCiphertext || !accessHash || !ownerHash || !mode) return bad("Missing required capsule data.");
  if (!/^[a-f0-9]{64}$/i.test(accessHash) || !/^[a-f0-9]{64}$/i.test(ownerHash)) return bad("Credential hashes must be SHA-256 hex.");
  const allowedModes = new Set(["standard", "one-time", "approval", "timed", "multi-approval", "dead-drop"]);
  if (!allowedModes.has(mode)) return bad("Unsupported capsule mode.");
  const id = requestedId && /^[A-Z0-9]{16}$/i.test(requestedId) ? requestedId.toUpperCase() : randomId(8).toUpperCase();
  const ts = now();
  let expiresAt = Number(body.expiresAt || 0) || null;
  if (expiresAt && (expiresAt <= ts || expiresAt > ts + 3650 * 24 * 60 * 60 * 1000)) return bad("Invalid expiration.");
  const oneTime = mode === "one-time" ? 1 : body.oneTime ? 1 : 0;
  await env.DB.prepare(
    "INSERT INTO capsules (id,access_hash,owner_hash,envelope,payload_ciphertext,metadata_ciphertext,mode,status,one_time,expires_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  ).bind(id, accessHash, ownerHash, envelope, payloadCiphertext, metadataCiphertext, mode, "active", oneTime, expiresAt, ts, ts).run();
  await audit(env.DB, id, "capsule.created", `mode=${mode}`, null);
  return json({ id, status: "active", expiresAt });
}

async function requestAccess(request, env) {
  const body = await readJson(request);
  const capsuleId = cleanString(body.capsuleId, 32);
  const accessHash = cleanString(body.accessHash, 128);
  if (!capsuleId || !accessHash) return bad("capsuleId and accessHash are required.");
  if (!/^[a-f0-9]{64}$/i.test(accessHash)) return bad("Invalid access credential.", 401, "UNAUTHORIZED");
  const capsule = await env.DB.prepare("SELECT * FROM capsules WHERE id=? AND access_hash=? LIMIT 1").bind(capsuleId, accessHash.toLowerCase()).first();
  const state = await capsuleIsOpenable(env.DB, capsule);
  if (!state.ok) return bad(state.message, state.status, state.code);
  const context = clientContext(request);
  const sessionId = randomId(10).toUpperCase();
  const ts = now();
  const autoApprove = new Set(["standard", "timed", "one-time"]).has(capsule.mode);
  const initialState = autoApprove ? "approved" : "pending";
  await env.DB.batch([
    env.DB.prepare("INSERT INTO sessions (id,capsule_id,state,device,os,browser,region,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(sessionId, capsuleId, initialState, context.device, context.os, context.browser, context.region, ts, ts),
    env.DB.prepare("INSERT INTO approvals (capsule_id,session_id,decision,created_at,decided_at,actor) VALUES (?,?,?,?,?,?)").bind(capsuleId, sessionId, initialState, ts, autoApprove ? ts : null, autoApprove ? "policy" : null)
  ]);
  await audit(env.DB, capsuleId, "access.requested", `device=${context.device};os=${context.os};browser=${context.browser};region=${context.region}`, sessionId);
  if (autoApprove) await audit(env.DB, capsuleId, "access.auto_approved", `mode=${capsule.mode}`, sessionId);
  return json({ sessionId, state: initialState, capsuleId });
}

async function getSession(request, env, url) {
  const capsuleId = cleanString(url.searchParams.get("capsuleId"), 32);
  const sessionId = cleanString(url.searchParams.get("sessionId"), 64);
  if (!capsuleId || !sessionId) return bad("Missing session parameters.");
  const row = await env.DB.prepare(
    "SELECT s.*, c.status AS capsule_status, c.expires_at, c.one_time, c.consumed_at FROM sessions s JOIN capsules c ON c.id=s.capsule_id WHERE s.id=? AND s.capsule_id=? LIMIT 1"
  ).bind(sessionId, capsuleId).first();
  if (!row) return bad("Session not found.", 404, "NOT_FOUND");
  if (row.created_at + SESSION_TTL_MS < now() && row.state === "pending") {
    await env.DB.prepare("UPDATE sessions SET state='expired', updated_at=? WHERE id=?").bind(now(), sessionId).run();
    row.state = "expired";
  }
  if (row.expires_at && row.expires_at <= now()) {
    await env.DB.prepare("UPDATE capsules SET status='expired', updated_at=? WHERE id=? AND status='active'").bind(now(), capsuleId).run();
    row.capsule_status = "expired";
  }
  return json({
    sessionId,
    capsuleId,
    state: row.state,
    capsuleStatus: row.capsule_status,
    expiresAt: row.expires_at,
    consumed: !!row.consumed_at
  });
}

async function ownerDecision(request, env) {
  const body = await readJson(request);
  const capsuleId = cleanString(body.capsuleId, 32);
  const sessionId = cleanString(body.sessionId, 64);
  const ownerHash = cleanString(body.ownerHash, 128);
  const decision = cleanString(body.decision, 16);
  if (!capsuleId || !sessionId || !ownerHash || !["approved", "denied", "revoked"].includes(decision)) return bad("Invalid decision.");
  if (!await ownerAuth(env, capsuleId, ownerHash)) return bad("Owner authentication required.", 403, "FORBIDDEN");
  const capsule = await env.DB.prepare("SELECT * FROM capsules WHERE id=? LIMIT 1").bind(capsuleId).first();
  const state = await capsuleIsOpenable(env.DB, capsule);
  if (!state.ok && decision !== "revoked") return bad(state.message, state.status, state.code);
  const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND capsule_id=? LIMIT 1").bind(sessionId, capsuleId).first();
  if (!session) return bad("Session not found.", 404, "NOT_FOUND");
  const ts = now();
  if (decision === "revoked") {
    await env.DB.batch([
      env.DB.prepare("UPDATE sessions SET state='revoked', updated_at=? WHERE capsule_id=?").bind(ts, capsuleId),
      env.DB.prepare("UPDATE approvals SET decision='revoked', decided_at=? WHERE capsule_id=? AND decision='pending'").bind(ts, capsuleId),
      env.DB.prepare("UPDATE capsules SET status='locked', updated_at=? WHERE id=?").bind(ts, capsuleId)
    ]);
    await audit(env.DB, capsuleId, "access.revoked", "owner revoked active access", sessionId);
    return json({ state: "revoked", capsuleStatus: "locked" });
  }
  await env.DB.prepare("UPDATE approvals SET decision=?, decided_at=? WHERE session_id=? AND capsule_id=?").bind(decision, ts, sessionId, capsuleId).run();
  await env.DB.prepare("UPDATE sessions SET state=?, updated_at=? WHERE id=? AND capsule_id=?").bind(decision, ts, sessionId, capsuleId).run();
  await audit(env.DB, capsuleId, `access.${decision}`, `session=${sessionId}`, sessionId);
  return json({ state: decision, capsuleStatus: capsule.status });
}

async function openCapsule(request, env) {
  const body = await readJson(request);
  const capsuleId = cleanString(body.capsuleId, 32);
  const sessionId = cleanString(body.sessionId, 64);
  if (!capsuleId || !sessionId) return bad("Missing capsuleId or sessionId.");
  const capsule = await env.DB.prepare("SELECT * FROM capsules WHERE id=? LIMIT 1").bind(capsuleId).first();
  const state = await capsuleIsOpenable(env.DB, capsule);
  if (!state.ok) return bad(state.message, state.status, state.code);
  const session = await env.DB.prepare("SELECT * FROM sessions WHERE id=? AND capsule_id=? LIMIT 1").bind(sessionId, capsuleId).first();
  if (!session || session.state !== "approved") return bad("Session is not approved.", 403, "NOT_APPROVED");

  let consumedNow = false;
  if (capsule.one_time) {
    const claim = await env.DB.prepare("UPDATE capsules SET consumed_at=?, updated_at=? WHERE id=? AND one_time=1 AND consumed_at IS NULL AND status='active'").bind(now(), now(), capsuleId).run();
    if (!claim.meta?.changes) return bad("One-time capsule has already been consumed.", 409, "CONSUMED");
    consumedNow = true;
    await audit(env.DB, capsuleId, "capsule.consumed", "one-time open committed", sessionId);
  }
  await audit(env.DB, capsuleId, "capsule.opened", "ciphertext released to approved client", sessionId);
  return json({
    capsule: {
      id: capsule.id,
      mode: capsule.mode,
      envelope: JSON.parse(capsule.envelope),
      payloadCiphertext: JSON.parse(capsule.payload_ciphertext),
      metadataCiphertext: JSON.parse(capsule.metadata_ciphertext),
      expiresAt: capsule.expires_at,
      consumedNow
    }
  });
}

async function ownerAuth(env, capsuleId, ownerHash) {
  if (!ownerHash || !/^[a-f0-9]{64}$/i.test(ownerHash)) return false;
  const row = await env.DB.prepare("SELECT owner_hash FROM capsules WHERE id=? LIMIT 1").bind(capsuleId).first();
  return !!row && row.owner_hash === ownerHash.toLowerCase();
}

async function capsuleActivity(request, env, url) {
  let capsuleId = cleanString(url.searchParams.get("capsuleId"), 32);
  let ownerHash = cleanString(url.searchParams.get("ownerHash"), 128);
  if (request.method === "POST") {
    const body = await readJson(request);
    capsuleId = cleanString(body.capsuleId, 32);
    ownerHash = cleanString(body.ownerHash, 128);
  }
  if (!capsuleId || !await ownerAuth(env, capsuleId, ownerHash)) return bad("Owner authentication required.", 403, "FORBIDDEN");
  const capsule = await env.DB.prepare("SELECT id,status,mode,one_time,consumed_at,expires_at,created_at,updated_at FROM capsules WHERE id=? LIMIT 1").bind(capsuleId).first();
  if (!capsule) return bad("Capsule not found.", 404, "NOT_FOUND");
  const sessions = await env.DB.prepare("SELECT id,state,device,os,browser,region,created_at,updated_at FROM sessions WHERE capsule_id=? ORDER BY created_at DESC LIMIT 25").bind(capsuleId).all();
  const events = await env.DB.prepare("SELECT id,event_type,session_id,detail,created_at,event_hash,previous_hash FROM audit_events WHERE capsule_id=? ORDER BY id DESC LIMIT 50").bind(capsuleId).all();
  return json({ capsule, sessions: sessions.results || [], events: events.results || [] });
}

async function handleApi(request, env) {
  if (request.method === "OPTIONS") return json({ ok: true }, 204);
  if (!originAllowed(request)) return bad("Origin rejected.", 403, "FORBIDDEN");
  const url = new URL(request.url);
  const path = url.pathname;
  try {
    if (request.method === "POST" && path === "/api/capsules") return await createCapsule(request, env);
    if (request.method === "POST" && path === "/api/access/request") return await requestAccess(request, env);
    if (request.method === "GET" && path === "/api/access/session") return await getSession(request, env, url);
    if (request.method === "POST" && path === "/api/access/decision") return await ownerDecision(request, env);
    if (request.method === "POST" && path === "/api/capsules/open") return await openCapsule(request, env);
    if ((request.method === "GET" || request.method === "POST") && path === "/api/capsules/activity") return await capsuleActivity(request, env, url);
    if (path.startsWith("/api/")) return bad("Not found.", 404, "NOT_FOUND");
    return null;
  } catch (error) {
    const message = error?.message === "PAYLOAD_TOO_LARGE" ? "Payload too large." : error?.message === "INVALID_JSON" ? "Invalid JSON." : "Server error.";
    return bad(message, error?.message === "PAYLOAD_TOO_LARGE" ? 413 : 500, "SERVER_ERROR");
  }
}

export default {
  async fetch(request, env) {
    const api = await handleApi(request, env);
    if (api) return withCors(api);
    if (new URL(request.url).pathname.startsWith("/c/")) {
      const root = new URL(request.url);
      root.pathname = "/";
      root.search = "";
      return env.ASSETS.fetch(new Request(root, request));
    }
    return env.ASSETS.fetch(request);
  },
  async scheduled(_event, env) {
    const cutoff = now();
    await env.DB.prepare("UPDATE capsules SET status='expired', updated_at=? WHERE status='active' AND expires_at IS NOT NULL AND expires_at<=?").bind(cutoff, cutoff).run();
    await env.DB.prepare("UPDATE sessions SET state='expired', updated_at=? WHERE state='pending' AND created_at<=?").bind(cutoff, cutoff - SESSION_TTL_MS).run();
    await env.DB.prepare("DELETE FROM audit_events WHERE capsule_id IN (SELECT id FROM capsules WHERE status='expired' AND updated_at<?)").bind(cutoff - 7 * 24 * 60 * 60 * 1000).run();
  }
};
