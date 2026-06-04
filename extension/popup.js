// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const $ = (id) => document.getElementById(id);

$("open-options").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

let pageHasPasswordField = false;
let pageHasPasswordValue = false;

function setStatus(state, text) {
  const pill = $("status-pill");
  pill.classList.remove("pill-pending", "pill-ok", "pill-err");
  pill.classList.add(`pill-${state}`);
  $("status-text").textContent = text;
}

function setResult(kind, text) {
  const el = $("result");
  el.classList.remove("hidden", "ok", "err", "info");
  if (!kind) {
    el.classList.add("hidden");
    el.textContent = "";
    return;
  }
  el.classList.add(kind);
  el.textContent = text;
}

function friendlyError(e) {
  switch (e?.code) {
    case 3:
      return {
        kind: "info",
        text: "No password saved for this site yet. Type a username and tap Save password.",
      };
    case 4:
      return { kind: "info", text: "Request rejected on Prime." };
    case 5:
      return { kind: "err", text: "Prime didn't respond in time. Try again." };
    case 6:
      return { kind: "err", text: "Unlock Prime with your PIN, then try again." };
    case 7:
      return { kind: "err", text: "Session expired. Try again." };
    default:
      return { kind: "err", text: e?.message || String(e) };
  }
}

function setActionsEnabled(on) {
  // Fill needs a password field on the page (no username — device knows it).
  // Save needs a username and a password value typed on the page.
  // Generate just needs a username.
  const u = $("username").value.trim();
  $("fill").disabled = !on || !pageHasPasswordField;
  $("generate").disabled = !on || !u;
  $("save").disabled = !on || !u || !pageHasPasswordValue;
}

async function showActiveSite() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return null;
    const url = new URL(tab.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const host = url.host;
    $("site-host").textContent = host;
    $("site-monogram").textContent = host[0]?.toUpperCase() || "?";
    $("site").classList.remove("hidden");
    return tab;
  } catch {
    return null;
  }
}

async function probeForm(tab) {
  if (!tab) return null;
  try {
    return await chrome.tabs.sendMessage(tab.id, { kind: "read-form" });
  } catch {
    return null;
  }
}

async function refreshStatus() {
  setStatus("pending", "Connecting");
  try {
    const resp = await chrome.runtime.sendMessage({ method: "ping" });
    if (resp && resp.result) {
      setStatus("ok", "Connected to Passport Prime");
      $("form").classList.remove("hidden");
      $("actions").classList.remove("hidden");
    } else if (resp && resp.error) {
      setStatus("err", resp.error.message || "error");
    } else {
      setStatus("err", "No response");
    }
  } catch (e) {
    setStatus("err", String(e?.message || e));
  }
}

async function init() {
  const tab = await showActiveSite();
  await refreshStatus();
  const form = await probeForm(tab);

  if (form) {
    pageHasPasswordField = !!form.has_password_field;
    pageHasPasswordValue = !!form.password;
    if (form.username) {
      $("username").value = form.username;
      $("username-hint").textContent = "Detected from the page";
      $("username-hint").classList.remove("hidden");
      $("username-hint").classList.add("detected");
    } else {
      $("username-hint").textContent = "No username found on page; type one to continue";
      $("username-hint").classList.remove("hidden", "detected");
    }
  }
  setActionsEnabled(true);
}

$("username").addEventListener("input", () => {
  $("username-hint").classList.add("hidden");
  setActionsEnabled(true);
});

function disableAllActions() {
  $("fill").disabled = true;
  $("save").disabled = true;
  $("generate").disabled = true;
}

async function runAction(action, pendingText, verbForResult) {
  const username = $("username").value.trim();
  if (!username) {
    setResult("err", "Username required");
    return;
  }
  setResult("info", pendingText);
  disableAllActions();
  try {
    const resp = await chrome.runtime.sendMessage({ action, username });
    if (resp.error) throw resp.error;
    const { username: stored, action: storeAction } = resp.result;
    const verb = storeAction === "saved"
      ? `${verbForResult} for`
      : storeAction === "updated"
      ? `${verbForResult} (updated) for`
      : `${verbForResult} (restored) for`;
    setResult("ok", `${verb} ${stored}`);
  } catch (e) {
    const { kind, text } = friendlyError(e);
    setResult(kind, text);
  } finally {
    setActionsEnabled(true);
  }
}

async function runFillAction() {
  setResult("info", "Approve on device…");
  disableAllActions();
  try {
    const resp = await chrome.runtime.sendMessage({ action: "fill-active-tab" });
    if (resp.error) throw resp.error;
    const { username } = resp.result;
    setResult("ok", `Filled for ${username}`);
    setTimeout(() => window.close(), 700);
  } catch (e) {
    const { kind, text } = friendlyError(e);
    setResult(kind, text);
  } finally {
    setActionsEnabled(true);
  }
}

$("fill").addEventListener("click", runFillAction);
$("save").addEventListener("click", () =>
  runAction("save-active-tab", "Approve on device…", "Saved"),
);
$("generate").addEventListener("click", () =>
  runAction("generate-active-tab", "Approve on device…", "Generated"),
);

init();