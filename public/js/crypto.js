const te = new TextEncoder();
const td = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  return btoa(binary);
}
function base64ToBytes(base64) {
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function toHex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, "0")).join(""); }
function randomBytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }

async function hkdf(inputBytes, info, length = 32, salt = new Uint8Array(32)) {
  const base = await crypto.subtle.importKey("raw", inputBytes, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: te.encode(info) }, base, length * 8);
  return new Uint8Array(bits);
}

async function aesKey(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function aesEncrypt(keyBytes, plainBytes, aad = "") {
  const key = await aesKey(keyBytes);
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad), tagLength: 128 }, key, plainBytes);
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(cipher)), aad };
}
async function aesDecrypt(keyBytes, record) {
  const key = await aesKey(keyBytes);
  const iv = base64ToBytes(record.iv);
  const cipher = base64ToBytes(record.ciphertext);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: te.encode(record.aad || ""), tagLength: 128 }, key, cipher);
  return new Uint8Array(plain);
}

async function passwordKdf(password, saltBytes, iterations = 250000) {
  const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations }, base, 256);
  return new Uint8Array(bits);
}

async function sha256Hex(input) {
  const value = typeof input === "string" ? te.encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", value);
  return toHex(new Uint8Array(digest));
}

function generateCapsuleId() {
  return toHex(randomBytes(8)).toUpperCase();
}

function generateAccessCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const a = randomBytes(10);
  const chunks = [];
  for (let i = 0; i < 10; i++) chunks.push(alphabet[a[i] % alphabet.length]);
  return `${chunks.slice(0, 5).join("")}-${chunks.slice(5).join("")}`;
}

async function createCapsulePackage(message, options = {}) {
  const mode = options.mode || "standard";
  const capsuleId = options.capsuleId || "PENDING";
  const rootSecret = randomBytes(32);
  const contentKey = await hkdf(rootSecret, "cipher/content/v1", 32);
  const metadataKey = await hkdf(rootSecret, "cipher/metadata/v1", 32);
  const capsuleKey = await hkdf(rootSecret, "cipher/capsule/v1", 32);
  const auditKey = await hkdf(rootSecret, "cipher/audit/v1", 32);
  const secretKey = randomBytes(32);
  const ownerKey = randomBytes(32);
  const accessCode = generateAccessCode();
  const accessHash = await sha256Hex(accessCode);
  const ownerHash = await sha256Hex(toHex(ownerKey));

  const messageRecord = await aesEncrypt(contentKey, te.encode(message), `cipher|${capsuleId}|content|v1`);
  const metadata = {
    version: 1,
    type: "secure-capsule",
    mode,
    createdAt: new Date().toISOString(),
    language: options.language || "auto"
  };
  const metadataRecord = await aesEncrypt(metadataKey, te.encode(JSON.stringify(metadata)), `cipher|${capsuleId}|metadata|v1`);
  const wrapSalt = randomBytes(32);
  const envelopeKey = await hkdf(secretKey, "cipher/keywrap/v1", 32, wrapSalt);
  const envelopeCipher = await aesEncrypt(envelopeKey, te.encode(JSON.stringify({ rootSecret: bytesToBase64(rootSecret) })), `cipher|${capsuleId}|envelope|v1`);
  const envelope = { version: 1, wrapSalt: bytesToBase64(wrapSalt), ...envelopeCipher };

  return {
    clientSecret: toHex(secretKey),
    ownerKey: toHex(ownerKey),
    accessCode,
    accessHash,
    ownerHash,
    mode,
    messageRecord,
    metadataRecord,
    envelope,
    capsuleKey: bytesToBase64(capsuleKey)
  };
}

async function openCapsulePackage(secretKeyHex, capsuleId, capsule) {
  const secretKey = Uint8Array.from(secretKeyHex.match(/.{2}/g).map(x => parseInt(x, 16)));
  if (!/^[a-f0-9]{64}$/.test(secretKeyHex)) throw new Error("Invalid secret key format");
  const envelope = capsule.envelope;
  const wrapSalt = base64ToBytes(envelope.wrapSalt);
  const envelopeKey = await hkdf(secretKey, "cipher/keywrap/v1", 32, wrapSalt);
  const envelopePlain = await aesDecrypt(envelopeKey, envelope);
  const wrapped = JSON.parse(td.decode(envelopePlain));
  const rootSecret = base64ToBytes(wrapped.rootSecret);
  const contentKey = await hkdf(rootSecret, "cipher/content/v1", 32);
  const metadataKey = await hkdf(rootSecret, "cipher/metadata/v1", 32);
  const messagePlain = await aesDecrypt(contentKey, capsule.messageRecord, `cipher|${capsuleId}|content|v1`);
  const metadataPlain = await aesDecrypt(metadataKey, capsule.metadataCiphertext, `cipher|${capsuleId}|metadata|v1`);
  return { message: td.decode(messagePlain), metadata: JSON.parse(td.decode(metadataPlain)), integrity: true };
}

export { bytesToBase64, base64ToBytes, toHex, randomBytes, hkdf, aesEncrypt, aesDecrypt, passwordKdf, sha256Hex, generateCapsuleId, generateAccessCode, createCapsulePackage, openCapsulePackage };
