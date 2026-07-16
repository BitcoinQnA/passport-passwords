// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const $ = (id) => document.getElementById(id);

const FOUNDATION_PASSPORT_FILTER = {
  vendorId: 0x1307,
  productId: 0x0165,
};

const PAIRING_FILTERS = [
  FOUNDATION_PASSPORT_FILTER,
  {
    classCode: 0xff,
    subclassCode: 0x50,
    protocolCode: 0x01,
  },
];

$("open-options").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

let pageHasPasswordField = false;
let pageHasPasswordValue = false;
let matchingCredentials = [];
let credentialsLoaded = false;
let selectedUsername = "";

function setStatus(state, text) {
  const pill = $("status-pill");
  pill.classList.remove("pill-pending", "pill-ok", "pill-err");
  pill.classList.add(`pill-${state}`);
  $("status-text").textContent = text;
  $("pair").classList.toggle("hidden", state !== "err");
}

async function resetUsbTransport() {
  try {
    await chrome.runtime.sendMessage({ action: "reset-usb-transport" });
  } catch {}
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
  const message = String(e?.message || e || "");
  switch (e?.code) {
    case 3:
      return {
        kind: "info",
        text: "No password saved for this site yet. Type a username and choose Save to Passport.",
      };
    case 4:
      return { kind: "info", text: "Request rejected on Passport." };
    case 5:
      return { kind: "err", text: "Passport Prime did not respond in time. Try again." };
    case 6:
      return { kind: "err", text: "Unlock Passport Prime with your PIN, then try again." };
    case 7:
      return { kind: "err", text: "Session expired. Try again." };
    case 10:
      return { kind: "info", text: "Choose a saved login to fill." };
    default:
      break;
  }
  if (/No Passport Prime paired/i.test(message)) {
    return { kind: "err", text: "Pair Passport Prime, then try again." };
  }
  if (/USB interface is not available/i.test(message)) {
    return {
      kind: "err",
      text: "Passport is paired, but Passwords USB is not available. Keep Passwords open, reconnect USB, then try again.",
    };
  }
  if (/USB interface did not respond/i.test(message)) {
    return {
      kind: "err",
      text: "Passport is paired, but Passwords did not answer. Use Pair / repair, then try again.",
    };
  }
  if (/disconnected|reconnect|not connected|Couldn't open Passport Prime/i.test(message)) {
    return { kind: "err", text: "Repair the Passport connection, then try again." };
  }
  if (/Open the Passwords app/i.test(message)) {
    return { kind: "err", text: "Keep Passwords open, reconnect USB, then try again." };
  }
  return { kind: "err", text: message };
}

function setActionsEnabled(on) {
  // Fill needs a password field on the page. The device knows the username.
  // Save needs a username and a password value typed on the page.
  // Generate just needs a username.
  const u = $("username").value.trim();
  $("fill").disabled =
    !on ||
    !pageHasPasswordField ||
    (credentialsLoaded && matchingCredentials.length === 0);
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

async function refreshMatches() {
  try {
    const resp = await chrome.runtime.sendMessage({ action: "list-active-credentials" });
    if (resp?.error) throw resp.error;
    matchingCredentials = resp.result?.credentials || [];
    credentialsLoaded = true;
    selectedUsername = matchingCredentials[0]?.username || "";
    renderMatches();
  } catch {
    matchingCredentials = [];
    credentialsLoaded = false;
    selectedUsername = "";
    renderMatches();
  }
}

function renderMatches() {
  const box = $("matches");
  const list = $("matches-list");
  list.textContent = "";
  box.classList.toggle("hidden", !credentialsLoaded);

  if (!credentialsLoaded) return;
  if (matchingCredentials.length === 0) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = "No saved logins for this site.";
    list.appendChild(empty);
    return;
  }

  for (const credential of matchingCredentials) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = `match-item${credential.username === selectedUsername ? " selected" : ""}`;
    const label = document.createElement("span");
    label.className = "match-label";
    label.textContent = credential.label || credential.username;
    const user = document.createElement("span");
    user.className = "match-user";
    user.textContent = credential.username;
    item.appendChild(label);
    if (credential.label) item.appendChild(user);
    item.addEventListener("click", () => {
      selectedUsername = credential.username;
      if (!$("username").value.trim()) $("username").value = credential.username;
      renderMatches();
      setActionsEnabled(true);
    });
    list.appendChild(item);
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
      const { text } = friendlyError(resp.error);
      setStatus("err", text);
    } else {
      setStatus("err", "No response");
    }
  } catch (e) {
    const { text } = friendlyError(e);
    setStatus("err", text);
  }
}

function isLikelyPassport(device) {
  return (
    (device.vendorId === FOUNDATION_PASSPORT_FILTER.vendorId &&
      device.productId === FOUNDATION_PASSPORT_FILTER.productId) ||
    /passport/i.test(device.productName || "")
  );
}

async function repairPairing() {
  if (!navigator.usb) {
    setResult("err", "WebUSB is not available in this browser.");
    return;
  }
  setResult("info", "Choose Passport Prime...");
  disableAllActions();
  try {
    await resetUsbTransport();
    const granted = await navigator.usb.getDevices();
    for (const device of granted.filter(isLikelyPassport)) {
      try { await device.close(); } catch {}
      try { await device.forget(); } catch {}
    }
    await navigator.usb.requestDevice({ filters: PAIRING_FILTERS });
    await resetUsbTransport();
    setResult("ok", "Passport Prime paired.");
    await refreshStatus();
    await refreshMatches();
  } catch (e) {
    if (e?.name === "NotFoundError") {
      setResult("err", "No Passport Prime found. Open Passwords on the device and reconnect USB.");
    } else {
      setResult("err", e?.message || String(e));
    }
    setStatus("err", "Not connected");
  } finally {
    setActionsEnabled(true);
  }
}

async function init() {
  const tab = await showActiveSite();
  await refreshStatus();
  const form = await probeForm(tab);
  await refreshMatches();

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

async function runAction(action, pendingText, resultVerbs) {
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
      ? resultVerbs.saved
      : storeAction === "updated"
      ? resultVerbs.updated
      : resultVerbs.restored;
    setResult("ok", `${verb} ${stored}`);
  } catch (e) {
    const { kind, text } = friendlyError(e);
    setResult(kind, text);
  } finally {
    setActionsEnabled(true);
  }
}

async function runFillAction() {
  if (matchingCredentials.length > 1 && !selectedUsername) {
    setResult("info", "Choose a saved login to fill.");
    return;
  }
  setResult("info", "Approve on Passport...");
  disableAllActions();
  try {
    const resp = await chrome.runtime.sendMessage({
      action: "fill-active-tab",
      username: selectedUsername,
    });
    if (resp.error) throw resp.error;
    const { username } = resp.result;
    setResult("ok", `Filled from Passport for ${username}`);
    setTimeout(() => window.close(), 700);
  } catch (e) {
    const { kind, text } = friendlyError(e);
    setResult(kind, text);
  } finally {
    setActionsEnabled(true);
  }
}

$("fill").addEventListener("click", runFillAction);
$("pair").addEventListener("click", repairPairing);
$("save").addEventListener("click", () =>
  runAction("save-active-tab", "Approve on Passport...", {
    saved: "Saved to Passport for",
    updated: "Updated on Passport for",
    restored: "Restored on Passport for",
  }),
);
$("generate").addEventListener("click", () =>
  runAction("generate-active-tab", "Approve on Passport...", {
    saved: "Generated on Passport for",
    updated: "Generated and updated on Passport for",
    restored: "Generated and restored on Passport for",
  }),
);

init();
