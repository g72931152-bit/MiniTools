import { createCapsulePackage, openCapsulePackage, sha256Hex, generateCapsuleId } from "./crypto.js";

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const state = { currentCapsule: null, pendingSession: null, activityTimer: null, lastPending: 0 };

function showToast(message, type = "info") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

async function api(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { "content-type": "application/json", ...(options.headers || {}) }, credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error?.message || `Request failed (${res.status})`);
  return data;
}

function section(name) {
  $$(".nav-btn").forEach(x => x.classList.toggle("active", x.dataset.section === name));
  $$(".panel").forEach(x => x.classList.toggle("active", x.id === `panel-${name}`));
}

function stage(step, done = false) {
  const el = $(`.stage[data-stage="${step}"]`);
  if (!el) return;
  el.classList.toggle("done", done);
  $(".stage-state", el).textContent = done ? "✓" : "…";
}

function resetStages() { $$(".stage").forEach(x => { x.classList.remove("done"); $(".stage-state", x).textContent = "—"; }); }

async function encrypt() {
  const message = $("#message").value;
  if (!message.trim()) return showToast("Введите сообщение.", "error");
  const mode = $("#mode").value;
  const duration = Number($("#expiration").value);
  const capsuleId = generateCapsuleId();
  resetStages();
  const steps = [1,2,3,4,5,6,7,8];
  for (const s of steps.slice(0, 3)) { stage(s, true); await new Promise(r => setTimeout(r, 90)); }
  const expiresAt = duration ? Date.now() + duration : null;
  const pack = await createCapsulePackage(message, { mode, capsuleId });
  stage(4, true); stage(5, true); stage(6, true); await new Promise(r => setTimeout(r, 90)); stage(7, true); stage(8, true);

  // Server receives ciphertext, encrypted metadata and a hash of the access code; plaintext and secretKey stay in the browser.
  const created = await api("/api/capsules", {
    method: "POST",
    body: JSON.stringify({
      envelope: JSON.stringify(pack.envelope),
      payloadCiphertext: JSON.stringify(pack.messageRecord),
      metadataCiphertext: JSON.stringify(pack.metadataRecord),
      accessHash: pack.accessHash,
      ownerHash: pack.ownerHash,
      capsuleId,
      mode,
      expiresAt
    })
  });
  const payload = JSON.stringify(pack.messageRecord);
  const storageRecord = { ...created, payload, clientSecret: pack.clientSecret, accessCode: pack.accessCode, ownerKey: pack.ownerKey, ownerHash: pack.ownerHash };
  localStorage.setItem(`cipher.owner.${capsuleId}`, JSON.stringify(storageRecord));
  state.currentCapsule = storageRecord;
  $("#created-id").textContent = capsuleId;
  $("#created-link").textContent = `${location.origin}/c/${capsuleId}`;
  $("#created-access").textContent = pack.accessCode;
  $("#created-secret").textContent = pack.clientSecret;
  $("#created-owner").textContent = pack.ownerKey;
  $("#result").hidden = false;
  showToast("Secure Capsule создана.", "success");
  loadActivity(capsuleId);
}

async function openOwnerCapsule(capsuleId) {
  const raw = localStorage.getItem(`cipher.owner.${capsuleId}`);
  if (!raw) throw new Error("Эта капсула не сохранена в браузере владельца.");
  const record = JSON.parse(raw);
  const capsule = await api(`/api/capsules/activity`, { method: "POST", body: JSON.stringify({ capsuleId, ownerHash: record.ownerHash }) });
  const session = capsule.sessions.find(s => s.state === "approved");
  if (!session) throw new Error("Нет одобренной сессии.");
  return openCapsulePackage(record.clientSecret, capsuleId, { envelope: record.envelope, metadataCiphertext: record.metadataCiphertext, messageRecord: JSON.parse(record.payload) });
}

async function requestAccess() {
  const capsuleId = $("#open-id").value.trim().toUpperCase();
  const accessCode = $("#open-access").value.trim().toUpperCase();
  const secretKey = $("#open-secret").value.trim();
  if (!capsuleId || !accessCode || !/^[a-f0-9]{64}$/i.test(secretKey)) return showToast("Проверьте Capsule ID, Access Code и Secret Key.", "error");
  const accessHash = await sha256Hex(accessCode);
  try {
    const created = await api("/api/access/request", { method: "POST", body: JSON.stringify({ capsuleId, accessHash }) });
    state.pendingSession = { capsuleId, sessionId: created.sessionId, secretKey };
    $("#session-state").textContent = "WAITING FOR OWNER";
    $("#session-id").textContent = created.sessionId;
    $("#open-status").hidden = false;
    pollSession();
  } catch (e) { showToast(e.message, "error"); }
}

async function pollSession() {
  const s = state.pendingSession;
  if (!s) return;
  try {
    const data = await api(`/api/access/session?capsuleId=${encodeURIComponent(s.capsuleId)}&sessionId=${encodeURIComponent(s.sessionId)}`, { method: "GET", headers: {} });
    $("#session-state").textContent = data.state.toUpperCase();
    if (data.state === "approved") {
      const opened = await api("/api/capsules/open", { method: "POST", body: JSON.stringify({ capsuleId: s.capsuleId, sessionId: s.sessionId }) });
      const capsule = opened.capsule;
      const result = await openCapsulePackage(s.secretKey, s.capsuleId, { envelope: capsule.envelope, metadataCiphertext: capsule.metadataCiphertext, messageRecord: capsule.payloadCiphertext });
      $("#plaintext").textContent = result.message;
      $("#open-result").hidden = false;
      showToast("Integrity verified. Plaintext доступен.", "success");
      return;
    }
    if (["denied", "revoked", "expired"].includes(data.state)) return;
  } catch (e) {
    $("#session-state").textContent = e.message;
    return;
  }
  setTimeout(pollSession, 1800);
}

async function loadActivity(capsuleId) {
  try {
    const raw = localStorage.getItem(`cipher.owner.${capsuleId}`);
    if (!raw) throw new Error("Owner record not found in this browser.");
    const owner = JSON.parse(raw);
    const data = await api(`/api/capsules/activity`, { method: "POST", body: JSON.stringify({ capsuleId, ownerHash: owner.ownerHash }) });
    const sessions = $("#sessions");
    sessions.innerHTML = "";
    const pending = data.sessions.filter(s => s.state === "pending").length;
    if (pending > state.lastPending && state.lastPending >= 0) showToast(`${pending} pending access request${pending === 1 ? "" : "s"}.`);
    state.lastPending = pending;
    for (const s of data.sessions) {
      const row = document.createElement("div"); row.className = "session-row";
      row.innerHTML = `<div><b>${s.id}</b><small>${s.device} · ${s.os} · ${s.browser} · ${s.region}</small></div><span>${s.state.toUpperCase()}</span>`;
      if (s.state === "pending") {
        const actions = document.createElement("div"); actions.className = "row-actions";
        const approve = document.createElement("button"); approve.textContent = "APPROVE"; approve.onclick = () => decide(capsuleId, s.id, "approved");
        const deny = document.createElement("button"); deny.textContent = "DENY"; deny.onclick = () => decide(capsuleId, s.id, "denied");
        actions.append(approve, deny); row.appendChild(actions);
      }
      sessions.appendChild(row);
    }
    $("#events").textContent = data.events.map(e => `${new Date(e.created_at).toLocaleTimeString()}  ${e.event_type}  ${e.detail}`).join("\n");
  } catch {}
}

async function decide(capsuleId, sessionId, decision) {
  try {
    const raw = localStorage.getItem(`cipher.owner.${capsuleId}`);
  if (!raw) throw new Error("Owner record not found in this browser.");
  const owner = JSON.parse(raw);
  await api("/api/access/decision", { method: "POST", body: JSON.stringify({ capsuleId, sessionId, ownerHash: owner.ownerHash, decision }) });
    loadActivity(capsuleId);
  } catch (e) { showToast(e.message, "error"); }
}

async function revoke() {
  const id = $("#owner-capsule").value.trim().toUpperCase();
  const raw = localStorage.getItem(`cipher.owner.${id}`);
  if (!raw) return showToast("Owner record not found.", "error");
  const activity = await api(`/api/capsules/activity`, { method: "POST", body: JSON.stringify({ capsuleId: id, ownerHash: JSON.parse(raw).ownerHash }) });
  const session = activity.sessions[0];
  if (!session) return showToast("Нет активных сессий.", "error");
  try { await decide(id, session.id, "revoked"); showToast("Доступ отозван.", "success"); } catch (e) { showToast(e.message, "error"); }
}

function publishHandoff() {
  const id = $("#created-id").textContent.trim();
  if (!id) return;
  const raw = localStorage.getItem(`cipher.owner.${id}`);
  if (!raw) return;
  const record = JSON.parse(raw);
  showToast("Encrypted payload уже хранится в D1. Получателю нужны только Capsule ID, Access Code и Secret Key.", "success");
}

$$(".nav-btn").forEach(btn => btn.addEventListener("click", () => section(btn.dataset.section)));
$("#encrypt-btn").addEventListener("click", () => encrypt().catch(e => showToast(e.message, "error")));
$("#request-btn").addEventListener("click", requestAccess);
$("#refresh-activity").addEventListener("click", () => loadActivity($("#owner-capsule").value.trim().toUpperCase()));
$("#revoke-btn").addEventListener("click", revoke);
$("#handoff-btn").addEventListener("click", publishHandoff);
$("#owner-capsule").addEventListener("change", e => {
  const id = e.target.value.trim().toUpperCase();
  state.lastPending = 0;
  if (state.activityTimer) clearInterval(state.activityTimer);
  if (id) { loadActivity(id); state.activityTimer = setInterval(() => loadActivity(id), 2200); }
});
