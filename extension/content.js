// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Content script. Runs only in the top frame (manifest all_frames:false).
// Two responsibilities:
//   1) handle popup-driven read-form / fill messages from the service worker
//   2) attach a small "Passwords" overlay button next to password fields
//      that lets the user release a credential from Prime
//
// There is intentionally NO page-world API: any privileged action must be
// initiated by a user gesture (popup click or overlay click). Web pages
// cannot call into the bridge directly.

const PRIME_TEAL = "#269eb5";
const CLICK_DEBOUNCE_MS = 600;

// Suppress the save-on-change prompt when the password value matches one
// we just filled — avoids "save this?" prompts immediately after Fill.
const FILLED_VALUES = new WeakMap();
// Per-input flag: user already saw + handled (saved or dismissed) the
// prompt for the current value. Cleared if they type a different value.
const PROMPTED_VALUES = new WeakMap();

// Background -> content (popup-driven actions).
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return false;
  // Ignore messages from anywhere except our own extension's service worker.
  if (sender.id !== chrome.runtime.id || sender.tab) return false;
  if (msg.kind === "read-form") {
    sendResponse(readForm());
    return false;
  }
  if (msg.kind === "fill") {
    fillForm(msg.username, msg.password);
    sendResponse({ ok: true });
    return false;
  }
  return false;
});

function readForm() {
  const passwords = [...document.querySelectorAll('input[type="password"]')];
  const passwordInput =
    passwords.find((p) => p.value) || passwords[0] || null;
  const password = passwordInput ? passwordInput.value : "";
  const usernameField = passwordInput ? findUsernameField(passwordInput) : null;
  const username = usernameField ? usernameField.value : "";
  return {
    origin: window.location.origin,
    username,
    password,
    has_password_field: passwords.length > 0,
  };
}

function fillForm(username, password) {
  const passwords = [...document.querySelectorAll('input[type="password"]')];
  const passwordInput = passwords[0];
  if (!passwordInput) return false;
  setFieldValue(passwordInput, password);
  FILLED_VALUES.set(passwordInput, password);
  if (username) {
    const userField = findUsernameField(passwordInput);
    if (userField) setFieldValue(userField, username);
  }
  return true;
}

// --- Password-field overlay button ---------------------------------------
//
// One button per visible password input. Lives in a closed shadow root
// inside a host element appended to <body> so the page can't restyle it,
// reach its internals via querySelector, or read its textContent. Clicks
// must be `isTrusted` (real user) and we debounce to prevent rapid replay.

const ATTACHED = new WeakSet();

function attachOverlay(input) {
  if (ATTACHED.has(input)) return;
  ATTACHED.add(input);

  const host = document.createElement("div");
  host.style.cssText =
    "position:absolute;z-index:2147483647;top:0;left:0;pointer-events:none;";
  document.body.appendChild(host);
  const root = host.attachShadow({ mode: "closed" });

  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = "Passwords";
  btn.title = "Fill from Passport Prime";
  btn.style.cssText = [
    "pointer-events:auto",
    "padding:5px 10px",
    "font-size:11px",
    "font-weight:600",
    "line-height:1",
    `border:1px solid ${PRIME_TEAL}`,
    "border-radius:6px",
    `background:${PRIME_TEAL}`,
    "color:#ffffff",
    "font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',sans-serif",
    "box-shadow:0 2px 6px rgba(0,0,0,0.2)",
    "cursor:pointer",
  ].join(";");
  root.appendChild(btn);

  function reposition() {
    const r = input.getBoundingClientRect();
    host.style.top = `${window.scrollY + r.top + r.height + 4}px`;
    host.style.left = `${window.scrollX + r.left}px`;
  }
  reposition();
  window.addEventListener("scroll", reposition, true);
  window.addEventListener("resize", reposition);

  let lastClick = 0;
  let inflight = false;
  btn.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!e.isTrusted) return;
    const now = Date.now();
    if (inflight || now - lastClick < CLICK_DEBOUNCE_MS) return;
    lastClick = now;
    inflight = true;
    btn.textContent = "Approve on device…";
    btn.disabled = true;
    try {
      const resp = await chrome.runtime.sendMessage({
        method: "release_credential",
      });
      if (resp.error) throw resp.error;
      const { username, password } = resp.result;
      const userField = findUsernameField(input);
      if (userField && username) setFieldValue(userField, username);
      setFieldValue(input, password);
      FILLED_VALUES.set(input, password);
      btn.textContent = "Filled";
      setTimeout(() => {
        btn.textContent = "Passwords";
        btn.disabled = false;
        inflight = false;
      }, 1500);
    } catch {
      // Don't surface device-side error text to the page DOM.
      btn.textContent = "Failed";
      setTimeout(() => {
        btn.textContent = "Passwords";
        btn.disabled = false;
        inflight = false;
      }, 2000);
    }
  });
}

// --- Save-on-change prompt ----------------------------------------------
//
// One per password field. When the user types a value that we didn't fill
// (and isn't empty), show a small floating banner offering to save the
// credential to Prime. Click Save -> background's save-from-content path.
// Re-typing a different value clears the "already prompted" guard so the
// new value can be offered too.

const SAVE_WATCHED = new WeakSet();

function attachSavePrompt(input) {
  if (SAVE_WATCHED.has(input)) return;
  SAVE_WATCHED.add(input);

  let promptEl = null;

  function dismissPrompt() {
    if (promptEl) {
      promptEl.remove();
      promptEl = null;
    }
  }

  function shouldPrompt() {
    const value = input.value;
    if (!value) return false;
    if (FILLED_VALUES.get(input) === value) return false;
    if (PROMPTED_VALUES.get(input) === value) return false;
    return true;
  }

  function maybeShowPrompt() {
    if (!shouldPrompt()) return;
    dismissPrompt();
    promptEl = renderSavePrompt(input, async () => {
      const password = input.value;
      const userField = findUsernameField(input);
      const username = userField ? userField.value : "";
      PROMPTED_VALUES.set(input, password);
      setPromptState(promptEl, "pending", "Approve on device…");
      try {
        const resp = await chrome.runtime.sendMessage({
          action: "save-from-content",
          username,
          password,
        });
        if (resp?.error) throw resp.error;
        setPromptState(promptEl, "ok", "Saved to Prime");
        setTimeout(dismissPrompt, 1500);
      } catch (e) {
        const code = e?.code;
        const text =
          code === 4
            ? "Rejected on Prime"
            : code === 1 && /username/.test(e?.message || "")
              ? "Username required"
              : "Save failed";
        setPromptState(promptEl, "err", text);
        setTimeout(dismissPrompt, 2000);
      }
    }, () => {
      PROMPTED_VALUES.set(input, input.value);
      dismissPrompt();
    });
  }

  input.addEventListener("input", (e) => {
    if (!e.isTrusted) return;
    // User changed the value -> previous prompt decision no longer applies.
    PROMPTED_VALUES.delete(input);
  });
  input.addEventListener("change", () => {
    if (!document.contains(input)) return;
    maybeShowPrompt();
  });
  input.addEventListener("blur", () => {
    if (!document.contains(input)) return;
    maybeShowPrompt();
  });
  const form = input.closest("form");
  if (form) {
    form.addEventListener(
      "submit",
      () => {
        maybeShowPrompt();
      },
      { capture: true },
    );
  }
}

function renderSavePrompt(input, onSave, onDismiss) {
  const host = document.createElement("div");
  host.style.cssText =
    "position:absolute;z-index:2147483647;top:0;left:0;pointer-events:none;";
  document.body.appendChild(host);
  const root = host.attachShadow({ mode: "closed" });

  const wrap = document.createElement("div");
  wrap.style.cssText = [
    "pointer-events:auto",
    "display:flex",
    "align-items:center",
    "gap:8px",
    "padding:8px 10px",
    "background:#18181b",
    "color:#f4f4f5",
    `border:1px solid ${PRIME_TEAL}`,
    "border-radius:8px",
    "font-size:12px",
    "font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI',sans-serif",
    "box-shadow:0 4px 14px rgba(0,0,0,0.35)",
    "max-width:340px",
  ].join(";");

  const label = document.createElement("span");
  label.textContent = "Save this password to Prime?";
  label.style.flex = "1";
  wrap.appendChild(label);

  const save = document.createElement("button");
  save.type = "button";
  save.textContent = "Save";
  save.style.cssText = [
    "padding:4px 10px",
    "border-radius:6px",
    "border:1px solid transparent",
    `background:${PRIME_TEAL}`,
    "color:#fff",
    "font-size:12px",
    "font-weight:600",
    "cursor:pointer",
  ].join(";");

  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.textContent = "Dismiss";
  dismiss.style.cssText = [
    "padding:4px 10px",
    "border-radius:6px",
    "border:1px solid #3f3f46",
    "background:transparent",
    "color:#a1a1aa",
    "font-size:12px",
    "cursor:pointer",
  ].join(";");

  wrap.appendChild(save);
  wrap.appendChild(dismiss);
  root.appendChild(wrap);

  function reposition() {
    const r = input.getBoundingClientRect();
    host.style.top = `${window.scrollY + r.top + r.height + 36}px`;
    host.style.left = `${window.scrollX + r.left}px`;
  }
  reposition();
  window.addEventListener("scroll", reposition, true);
  window.addEventListener("resize", reposition);

  save.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    onSave();
  });
  dismiss.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    onDismiss();
  });

  // Tag for setPromptState to find.
  host.__vbPromptParts = { wrap, label, save, dismiss };
  return host;
}

function setPromptState(host, state, text) {
  if (!host || !host.__vbPromptParts) return;
  const { label, save, dismiss } = host.__vbPromptParts;
  label.textContent = text;
  const colors = { pending: "#fbbf24", ok: "#4ade80", err: "#f87171" };
  if (colors[state]) label.style.color = colors[state];
  save.disabled = true;
  save.style.opacity = "0.5";
  dismiss.disabled = state !== "err";
}

function findUsernameField(passwordField) {
  const form = passwordField.closest("form");
  const scope = form || document;
  const candidates = [
    ...scope.querySelectorAll(
      'input[type="text"], input[type="email"], input[autocomplete*="username"], input[name*="user" i], input[name*="email" i]',
    ),
  ].filter((el) => el.offsetParent !== null);
  // Prefer the field directly preceding the password field if any; else
  // the last visible candidate as a fallback for multi-step forms.
  if (!candidates.length) return null;
  for (let i = candidates.length - 1; i >= 0; i--) {
    const relation = candidates[i].compareDocumentPosition(passwordField);
    if (relation & Node.DOCUMENT_POSITION_FOLLOWING) return candidates[i];
  }
  return candidates[candidates.length - 1];
}

function setFieldValue(input, value) {
  const proto = Object.getPrototypeOf(input);
  const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
  setter.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function scan() {}

scan();
const obs = new MutationObserver(scan);
obs.observe(document.documentElement, { childList: true, subtree: true });