/**
 * 片付けマスター3D SHOP - Cloudflare Worker API
 *
 * Routes:
 *   GET  /api/health
 *   POST /api/register
 *   POST /api/login
 *   POST /api/save
 *   GET  /api/load
 *   GET  /api/me
 *
 * Required binding:
 *   KV (Cloudflare Workers KV)
 *
 * Static files are served by Workers Assets through wrangler.jsonc.
 */

const PREFIX = "cm3d:v1:";
const PBKDF2_ITERATIONS = 100000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
const MAX_REQUEST_BYTES = 1_000_000;
const MAX_SAVE_BYTES = 900_000;
const encoder = new TextEncoder();

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function getKV(env) {
  const kv = env?.KV;
  if (!kv || typeof kv.get !== "function" || typeof kv.put !== "function") {
    throw new ApiError(
      503,
      "KV bindingがありません。既存KV NamespaceをVariable name=KVで接続してください。"
    );
  }
  return kv;
}

async function readJson(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > MAX_REQUEST_BYTES) {
    throw new ApiError(413, "送信データが大きすぎます。");
  }

  const raw = await request.text();
  if (encoder.encode(raw).byteLength > MAX_REQUEST_BYTES) {
    throw new ApiError(413, "送信データが大きすぎます。");
  }
  if (!raw) throw new ApiError(400, "送信データがありません。");

  try {
    return JSON.parse(raw);
  } catch {
    throw new ApiError(400, "JSONの形式が正しくありません。");
  }
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function randomBytes(length) {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), byte =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function derivePasswordHash(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    material,
    256
  );

  return bytesToBase64Url(new Uint8Array(derived));
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (left.length !== right.length) return false;

  let difference = 0;
  for (let index = 0; index < left.length; index++) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function credentialsFrom(body) {
  const username = String(body?.user ?? body?.username ?? "")
    .trim()
    .normalize("NFC");
  const password = String(body?.pass ?? body?.password ?? "");

  if (!username || username.length > 32) {
    throw new ApiError(400, "ユーザー名は1～32文字にしてください。");
  }
  if (/[\u0000-\u001f\u007f]/.test(username)) {
    throw new ApiError(400, "ユーザー名に使用できない文字があります。");
  }
  if (password.length < 4 || password.length > 128) {
    throw new ApiError(400, "パスワードは4～128文字にしてください。");
  }

  return { username, password };
}

async function userStorageKey(username) {
  const normalized = username.normalize("NFC").toLowerCase();
  return PREFIX + "user:" + await sha256Hex("username:" + normalized);
}

async function createSession(kv, account) {
  const token = bytesToBase64Url(randomBytes(32));
  const tokenHash = await sha256Hex("session:" + token);
  const now = Date.now();

  const session = {
    uid: account.id,
    username: account.username,
    createdAt: now,
    expiresAt: now + SESSION_TTL_SECONDS * 1000
  };

  await kv.put(
    PREFIX + "session:" + tokenHash,
    JSON.stringify(session),
    { expirationTtl: SESSION_TTL_SECONDS }
  );

  return token;
}

async function authenticate(request, kv) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new ApiError(401, "ログインが必要です。");

  const token = match[1].trim();
  if (!token || token.length > 512) {
    throw new ApiError(401, "ログイン情報が正しくありません。");
  }

  const tokenHash = await sha256Hex("session:" + token);
  const raw = await kv.get(PREFIX + "session:" + tokenHash);
  if (!raw) {
    throw new ApiError(401, "ログイン期限が切れています。再ログインしてください。");
  }

  let session;
  try {
    session = JSON.parse(raw);
  } catch {
    throw new ApiError(401, "ログイン情報が正しくありません。");
  }

  if (!session?.uid || !session?.expiresAt || session.expiresAt <= Date.now()) {
    throw new ApiError(401, "ログイン期限が切れています。再ログインしてください。");
  }

  return session;
}

async function register(request, kv) {
  const body = await readJson(request);
  const { username, password } = credentialsFrom(body);
  const key = await userStorageKey(username);

  // KVは分散ストアのため、重複チェックとputは完全なトランザクションではありません。
  if (await kv.get(key)) {
    throw new ApiError(409, "このユーザー名はすでに登録されています。");
  }

  const salt = randomBytes(16);
  const passwordHash = await derivePasswordHash(password, salt);

  const account = {
    id: crypto.randomUUID(),
    username,
    salt: bytesToBase64Url(salt),
    passwordHash,
    createdAt: Date.now()
  };

  await kv.put(key, JSON.stringify(account));
  const token = await createSession(kv, account);

  return json({
    ok: true,
    message: "登録に成功しました。",
    token,
    user: { id: account.id, name: account.username }
  });
}

async function login(request, kv) {
  const body = await readJson(request);
  const { username, password } = credentialsFrom(body);
  const key = await userStorageKey(username);
  const raw = await kv.get(key);

  if (!raw) {
    throw new ApiError(401, "ユーザー名またはパスワードが違います。");
  }

  let account;
  try {
    account = JSON.parse(raw);
  } catch {
    throw new ApiError(500, "アカウントデータを読み込めません。");
  }

  if (!account?.id || !account?.salt || !account?.passwordHash) {
    throw new ApiError(500, "アカウントデータが不完全です。");
  }

  let salt;
  try {
    salt = base64UrlToBytes(account.salt);
  } catch {
    throw new ApiError(500, "アカウントの暗号データが正しくありません。");
  }

  const actualHash = await derivePasswordHash(password, salt);
  if (!constantTimeEqual(actualHash, account.passwordHash)) {
    throw new ApiError(401, "ユーザー名またはパスワードが違います。");
  }

  const token = await createSession(kv, account);
  return json({
    ok: true,
    message: "ログインに成功しました。",
    token,
    user: { id: account.id, name: account.username }
  });
}

async function saveGame(request, kv, session) {
  const body = await readJson(request);

  if (!body || typeof body !== "object" ||
      !Object.prototype.hasOwnProperty.call(body, "data")) {
    throw new ApiError(400, "セーブデータがありません。");
  }
  if (!body.data || typeof body.data !== "object" || Array.isArray(body.data)) {
    throw new ApiError(400, "セーブデータの形式が正しくありません。");
  }

  const serialized = JSON.stringify(body.data);
  if (encoder.encode(serialized).byteLength > MAX_SAVE_BYTES) {
    throw new ApiError(413, "セーブデータが大きすぎます。");
  }

  await kv.put(PREFIX + "save:" + session.uid, serialized);
  return json({ ok: true, message: "保存しました。", savedAt: Date.now() });
}

async function loadGame(kv, session) {
  const raw = await kv.get(PREFIX + "save:" + session.uid);
  if (raw === null) {
    return json({ ok: true, data: null, message: "セーブデータはまだありません。" });
  }

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new ApiError(500, "セーブデータの形式が正しくありません。");
  }

  return json({ ok: true, data });
}

async function me(session) {
  return json({
    ok: true,
    user: { id: session.uid, name: session.username }
  });
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  if (path === "/api/health" && method === "GET") {
    const kvReady = !!env?.KV &&
      typeof env.KV.get === "function" &&
      typeof env.KV.put === "function";

    return json({
      ok: kvReady,
      status: "online",
      kv: kvReady
    }, kvReady ? 200 : 503);
  }

  if (path === "/api/health") {
    throw new ApiError(405, "GETでアクセスしてください。");
  }

  const kv = getKV(env);

  if (path === "/api/register") {
    if (method !== "POST") throw new ApiError(405, "POSTでアクセスしてください。");
    return register(request, kv);
  }

  if (path === "/api/login") {
    if (method !== "POST") throw new ApiError(405, "POSTでアクセスしてください。");
    return login(request, kv);
  }

  if (path === "/api/save" || path === "/api/load" || path === "/api/me") {
    const session = await authenticate(request, kv);

    if (path === "/api/save") {
      if (method !== "POST") throw new ApiError(405, "POSTでアクセスしてください。");
      return saveGame(request, kv, session);
    }
    if (path === "/api/load") {
      if (method !== "GET") throw new ApiError(405, "GETでアクセスしてください。");
      return loadGame(kv, session);
    }
    if (path === "/api/me") {
      if (method !== "GET") throw new ApiError(405, "GETでアクセスしてください。");
      return me(session);
    }
  }

  throw new ApiError(404, "APIルートが見つかりません。");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API以外はWorkers Assetsへ渡し、既存のindex.html/TEST999.htmlを配信します。
    if (!url.pathname.startsWith("/api/")) {
      if (env?.ASSETS?.fetch) return env.ASSETS.fetch(request);
      return new Response("Not Found", { status: 404 });
    }

    try {
      return await handleApi(request, env);
    } catch (error) {
      if (error instanceof ApiError) {
        return json({ ok: false, error: error.message }, error.status);
      }

      console.error("CM3D API ERROR:", error?.stack || error?.message || String(error));
      return json({
        ok: false,
        error: "サーバー内部エラーが発生しました。Cloudflare Logsを確認してください。"
      }, 500);
    }
  }
};
