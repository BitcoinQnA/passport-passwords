// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Service worker. Routes RPC from the content script and popup to the
// active transport (WebUSB via offscreen, or WebSocket simulator).
// Origin gate: derived from sender.tab.url for content-script requests;
// for popup/options requests we look up the active tab's URL ourselves.

const DEFAULT_WS = "ws://127.0.0.1:9876";
const DEFAULT_TRANSPORT = "webusb";

// Methods callable through the popup/content-script bridge. Privileged
// actions (release/store/generate) are never invoked directly by name from
// content scripts — they go through the high-level msg.action paths, which
// derive origin from sender.tab and run a single fresh user gesture. Only
// `release_credential` is reachable from the content-script overlay button
// path, with strict sender/frame validation in the router.
const METHODS = new Set([
  "ping",
  "release_credential",
]);

const SESSION_INFO = new TextEncoder().encode("vaults-bridge v1 session");

let ws = null;
let wsReady = null;
let wsQueue = new Map();
let wsServerUrl = DEFAULT_WS;
let transportKind = DEFAULT_TRANSPORT;
let rpcId = 0;

let hostPrivateKey = null;
let hostPublicKeyHex = null;
let sessionKey = null;
let requestNonce = 0;

async function loadConfig() {
  const cfg = await chrome.storage.local.get(["transportKind", "wsServerUrl"]);
  transportKind = cfg.transportKind === "ws" ? "ws" : "webusb";
  const candidate = cfg.wsServerUrl || DEFAULT_WS;
  // Hard-gate the simulator transport to loopback. A bug or compromised
  // options page could otherwise repoint at a remote attacker.
  wsServerUrl = isLoopbackWs(candidate) ? candidate : DEFAULT_WS;
}

function isLoopbackWs(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "ws:") return false;
    return u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]";
  } catch {
    return false;
  }
}

// Strip device-side error fields down to {code, message}. Anything else
// could leak internal state when forwarded to the popup or page DOM.
function sanitizeError(e) {
  if (typeof e === "object" && e && "code" in e) {
    return {
      code: typeof e.code === "number" ? e.code : 99,
      message: typeof e.message === "string" ? e.message.slice(0, 200) : "error",
    };
  }
  const message = typeof e?.message === "string" ? e.message : String(e);
  return { code: 99, message: message.slice(0, 200) };
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.transportKind) {
    transportKind = changes.transportKind.newValue;
    resetSession();
  }
  if (changes.wsServerUrl) wsServerUrl = changes.wsServerUrl.newValue;
});

function resetSession() {
  hostPrivateKey = null;
  hostPublicKeyHex = null;
  sessionKey = null;
  requestNonce = 0;
}

// --- WebSocket transport (simulator) -------------------------------------

function ensureWs() {
  if (ws && ws.readyState === WebSocket.OPEN) return Promise.resolve();
  if (wsReady) return wsReady;
  wsReady = new Promise((resolve, reject) => {
    try { ws = new WebSocket(wsServerUrl); }
    catch (e) { wsReady = null; reject(e); return; }
    ws.onopen = () => resolve();
    ws.onerror = (e) => {
      wsReady = null;
      reject(new Error(`ws error: ${e.message || "connect"}`));
    };
    ws.onclose = () => {
      wsReady = null;
      ws = null;
      resetSession();
      for (const [, entry] of wsQueue) entry.reject(new Error("ws closed"));
      wsQueue.clear();
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      const entry = wsQueue.get(msg.id);
      if (!entry) return;
      wsQueue.delete(msg.id);
      if (msg.error) entry.reject(msg.error);
      else entry.resolve(msg.result);
    };
  });
  return wsReady;
}

async function rpcWs(method, params) {
  await ensureWs();
  const id = String(++rpcId);
  const payload = params == null ? { id, method } : { id, method, params };
  return new Promise((resolve, reject) => {
    wsQueue.set(id, { resolve, reject });
    ws.send(JSON.stringify(payload));
    setTimeout(() => {
      if (wsQueue.has(id)) {
        wsQueue.delete(id);
        reject(new Error("ws rpc timeout"));
      }
    }, 5 * 60 * 1000);
  });
}

// --- WebUSB transport via offscreen --------------------------------------

const OFFSCREEN_PATH = "offscreen.html";
let offscreenReady = null;

async function ensureOffscreen() {
  if (offscreenReady) return offscreenReady;
  offscreenReady = (async () => {
    const has = await chrome.offscreen.hasDocument();
    if (!has) {
      try {
        await chrome.offscreen.createDocument({
          url: OFFSCREEN_PATH,
          reasons: ["WORKERS"],
          justification: "WebUSB requires a DOM context",
        });
      } catch (e) {
        offscreenReady = null;
        throw e;
      }
    }
  })();
  return offscreenReady;
}

async function rpcUsb(method, params) {
  await ensureOffscreen();
  const resp = await chrome.runtime.sendMessage({
    target: "offscreen-usb",
    type: "rpc",
    method,
    params,
  });
  if (!resp) throw new Error("no response from offscreen");
  if (!resp.ok) throw resp.error || new Error("usb rpc failed");
  return resp.result;
}

// All transport calls funnel through a single FIFO queue. Without this,
// concurrent popup actions (or rapid overlay clicks) issue request_nonce
// values out of order at the device, where strict monotonicity rejects
// the lower-arriving one.
let rpcChain = Promise.resolve();
function rpc(method, params) {
  const next = rpcChain.then(() => {
    if (transportKind === "ws") return rpcWs(method, params);
    return rpcUsb(method, params);
  });
  rpcChain = next.catch(() => {});
  return next;
}

// --- Session handshake (X25519 + HKDF -> AES-256-GCM) --------------------

async function ensureSession() {
  if (sessionKey) return;

  const kp = await crypto.subtle.generateKey(
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  hostPrivateKey = kp.privateKey;
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  hostPublicKeyHex = bytesToHex(pubRaw);

  const result = await rpc("establish_session", { host_pubkey: hostPublicKeyHex });
  const devicePubHex = result?.device_pubkey;
  if (!devicePubHex) throw new Error("no device_pubkey");
  const devicePubRaw = hexToBytes(devicePubHex);

  const peerPub = await crypto.subtle.importKey(
    "raw",
    devicePubRaw,
    { name: "X25519" },
    false,
    [],
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: peerPub },
    hostPrivateKey,
    256,
  );
  // Reject contributory failure: an all-zero shared secret means the peer
  // sent a low-order point. Without this, an attacker who can MITM the
  // pubkey exchange forces a known session key.
  const sharedBytes = new Uint8Array(sharedBits);
  if (sharedBytes.every((b) => b === 0)) {
    throw new Error("invalid X25519 shared secret");
  }
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const sessionKeyBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: SESSION_INFO,
    },
    hkdfKey,
    256,
  );
  sessionKey = await crypto.subtle.importKey(
    "raw",
    sessionKeyBits,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
  requestNonce = 0;
}

async function unsealPassword(sealedHex) {
  if (!sessionKey) throw new Error("session key missing");
  const raw = hexToBytes(sealedHex);
  if (raw.length < 12 + 16) throw new Error("sealed payload too short");
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, sessionKey, ct);
  return new TextDecoder().decode(plain);
}

async function sealPassword(plaintext) {
  if (!sessionKey) throw new Error("session key missing");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sessionKey,
    new TextEncoder().encode(plaintext),
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return bytesToHex(out);
}

// --- High-level orchestration for popup actions --------------------------

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) throw new Error("no active tab");
  const url = new URL(tab.url);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`unsupported page (${url.protocol})`);
  }
  return { tab, origin: url.origin };
}

async function readFormFromTab(tabId) {
  return await chrome.tabs.sendMessage(tabId, { kind: "read-form" });
}

async function fillFormInTab(tabId, payload) {
  return await chrome.tabs.sendMessage(tabId, { kind: "fill", ...payload });
}

async function saveActiveTab(suppliedUsername) {
  const { tab, origin } = await activeTab();
  const form = await readFormFromTab(tab.id).catch(() => null);
  if (!form || !form.password) {
    throw new Error("no password value found on the page");
  }
  // Popup-supplied username overrides what the form detection found
  // (necessary on multi-step signup flows where the password page has
  // no username field at all).
  const username = (suppliedUsername || form.username || "").trim();
  if (!username) {
    throw new Error("username required");
  }
  await ensureSession();
  const sealed = await sealPassword(form.password);
  const result = await rpc("store_credential", {
    origin,
    username,
    password_sealed: sealed,
    request_nonce: ++requestNonce,
  });
  return { origin, username, action: result.action };
}

async function fillActiveTab() {
  const { tab, origin } = await activeTab();
  await ensureSession();
  const result = await rpc("release_credential", {
    origin,
    request_nonce: ++requestNonce,
  });
  const password = await unsealPassword(result.password_sealed);
  await fillFormInTab(tab.id, { username: result.username, password });
  return { origin, username: result.username };
}

async function generateActiveTab(suppliedUsername) {
  const { tab, origin } = await activeTab();
  const form = await readFormFromTab(tab.id).catch(() => null);
  const username = (suppliedUsername || form?.username || "").trim();
  if (!username) {
    throw new Error("username required");
  }
  await ensureSession();
  const result = await rpc("generate_password", {
    origin,
    username,
    length: 24,
    request_nonce: ++requestNonce,
  });
  const password = await unsealPassword(result.password_sealed);
  // Best-effort fill: works on signup pages where the password field
  // exists; on pages with no password input the page just stays as-is.
  if (form?.has_password_field) {
    await fillFormInTab(tab.id, { username, password });
  }
  return { origin, username, action: result.action };
}

// --- Message router ------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return false;
  if (msg.target === "offscreen-usb") return false;

  // Reject anything that didn't come from our own extension. Defends
  // against a future externally_connectable misconfig and forms a clear
  // trust boundary: only popup pages and our own content scripts speak
  // to this listener.
  if (sender?.id !== chrome.runtime.id) return false;

  const fromContentScript = !!sender?.tab;
  const fromExtensionPage = !sender?.tab; // popup, options, offscreen

  // Popup-initiated high-level actions. Must come from an extension page
  // (no sender.tab), never from a content script.
  if (
    msg.action === "save-active-tab" ||
    msg.action === "generate-active-tab" ||
    msg.action === "fill-active-tab"
  ) {
    if (!fromExtensionPage) return false;
    (async () => {
      try {
        await loadConfig();
        let result;
        if (msg.action === "save-active-tab") result = await saveActiveTab(msg.username);
        else if (msg.action === "generate-active-tab") result = await generateActiveTab(msg.username);
        else result = await fillActiveTab();
        sendResponse({ result });
      } catch (e) {
        if (e?.code === 7) resetSession();
        sendResponse({ error: sanitizeError(e) });
      }
    })();
    return true;
  }

  // Content-script save-on-change. The content script has just watched
  // the user type into a password field on its tab; it sends the typed
  // username + password here. Origin is derived from sender.tab.url so
  // a tab can't impersonate another.
  if (msg.action === "save-from-content") {
    if (!fromContentScript) return false;
    if (sender.frameId !== 0) {
      sendResponse({ error: { code: 1, message: "top frame only" } });
      return false;
    }
    const tabOrigin = sender.tab?.url ? new URL(sender.tab.url).origin : null;
    if (!tabOrigin) {
      sendResponse({ error: { code: 1, message: "no tab origin" } });
      return false;
    }
    const username = (msg.username || "").trim();
    const password = msg.password || "";
    if (!username || !password) {
      sendResponse({ error: { code: 1, message: "username and password required" } });
      return false;
    }
    (async () => {
      try {
        await loadConfig();
        await ensureSession();
        const sealed = await sealPassword(password);
        const result = await rpc("store_credential", {
          origin: tabOrigin,
          username,
          password_sealed: sealed,
          request_nonce: ++requestNonce,
        });
        sendResponse({ result: { origin: tabOrigin, username, action: result.action } });
      } catch (e) {
        if (e?.code === 7) resetSession();
        sendResponse({ error: sanitizeError(e) });
      }
    })();
    return true;
  }

  if (!msg.method) return false;
  const method = String(msg.method);
  if (!METHODS.has(method)) {
    sendResponse({ error: { code: 2, message: "unknown method" } });
    return false;
  }
  (async () => {
    try {
      await loadConfig();
      const params = {};

      // ping: harmless, allowed from any extension surface.
      if (method === "ping") {
        const result = await rpc(method, null);
        sendResponse({ result });
        return;
      }

      // release_credential from the content-script overlay button. The
      // origin is ALWAYS derived from sender.tab.url — never trusted
      // from msg.params. Must come from the top frame; iframes are
      // refused so a sandboxed third-party embed can't drive a release
      // for the parent's origin.
      if (method === "release_credential") {
        if (!fromContentScript) {
          sendResponse({ error: { code: 1, message: "content script only" } });
          return;
        }
        if (sender.frameId !== 0) {
          sendResponse({ error: { code: 1, message: "top frame only" } });
          return;
        }
        const tabOrigin = sender.tab?.url
          ? new URL(sender.tab.url).origin
          : null;
        if (!tabOrigin) {
          sendResponse({ error: { code: 1, message: "no tab origin" } });
          return;
        }
        params.origin = tabOrigin;
        await ensureSession();
        params.request_nonce = ++requestNonce;
      }

      const result = await rpc(method, params);

      if (method === "release_credential" && result?.password_sealed) {
        const password = await unsealPassword(result.password_sealed);
        sendResponse({ result: { username: result.username, password } });
      } else {
        sendResponse({ result });
      }
    } catch (e) {
      if (e?.code === 7) resetSession();
      sendResponse({ error: sanitizeError(e) });
    }
  })();
  return true;
});

// --- hex helpers ---------------------------------------------------------

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  if (typeof hex !== "string") throw new Error("hex must be string");
  if (hex.length % 2) throw new Error("odd-length hex");
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

loadConfig();