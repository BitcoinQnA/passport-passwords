// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const $ = (id) => document.getElementById(id);

const FOUNDATION_PASSPORT_FILTER = {
  vendorId: 0x1307,
  productId: 0x0165,
};

const VENDOR_CLASS_FILTER = {
  classCode: 0xff,
  subclassCode: 0x50,
  protocolCode: 0x01,
};

const PAIRING_FILTERS = [
  FOUNDATION_PASSPORT_FILTER,
  VENDOR_CLASS_FILTER,
];

function isLikelyPassport(device) {
  return (
    (device.vendorId === FOUNDATION_PASSPORT_FILTER.vendorId &&
      device.productId === FOUNDATION_PASSPORT_FILTER.productId) ||
    /passport/i.test(device.productName || "")
  );
}

function setPair(state, text) {
  const dot = $("pair-dot");
  dot.classList.remove("ok", "err");
  if (state === "ok") dot.classList.add("ok");
  else if (state === "err") dot.classList.add("err");
  $("pair-status").textContent = text;
}

function friendlyPairStatus(error, names) {
  const message = String(error?.message || error || "");
  const label = names.length ? names.join(", ") : "Passport Prime";
  if (/No Passport Prime paired/i.test(message)) {
    return "No Passport Prime paired";
  }
  if (/USB interface is not available/i.test(message)) {
    return `Permission granted for ${label}, but Passwords USB is not available. Keep Passwords open and reconnect USB.`;
  }
  if (/USB interface did not respond/i.test(message)) {
    return `Permission granted for ${label}, but Passwords did not answer. Reconnect USB or pair again.`;
  }
  if (/disconnected|reconnect|not connected|Couldn't open Passport Prime/i.test(message)) {
    return `Permission granted for ${label}, but Passport Prime is disconnected. Reconnect USB.`;
  }
  if (/Open the Passwords app/i.test(message)) {
    return `Permission granted for ${label}, but Passwords is not reachable. Keep Passwords open and reconnect USB.`;
  }
  return `Permission granted for ${label}, but connection failed: ${message || "unknown error"}`;
}

async function resetUsbTransport() {
  try {
    await chrome.runtime.sendMessage({ action: "reset-usb-transport" });
  } catch {}
}

async function refreshPairStatus() {
  try {
    const granted = await navigator.usb.getDevices();
    const passports = granted.filter(isLikelyPassport);
    if (passports.length === 0) {
      setPair("idle", "No Passport Prime paired");
      return;
    }
    const names = passports.map((d) => d.productName || `${d.vendorId}:${d.productId}`);
    setPair("idle", `Permission granted: ${names.join(", ")}. Checking connection...`);
    try {
      const resp = await chrome.runtime.sendMessage({ method: "ping" });
      if (resp?.result) {
        setPair("ok", `Connected: ${names.join(", ")}`);
      } else if (resp?.error) {
        setPair("err", friendlyPairStatus(resp.error, names));
      } else {
        setPair("err", `Permission granted for ${names.join(", ")}, but Passport Prime did not respond.`);
      }
    } catch (e) {
      setPair("err", friendlyPairStatus(e, names));
    }
  } catch (e) {
    setPair("err", `WebUSB unavailable: ${e?.message || e}`);
  }
}

$("pair").addEventListener("click", async () => {
  try {
    await resetUsbTransport();
    await navigator.usb.requestDevice({ filters: PAIRING_FILTERS });
    await resetUsbTransport();
    await refreshPairStatus();
  } catch (e) {
    if (e?.name === "NotFoundError") {
      setPair(
        "err",
        "No Passport Prime found. Open Passwords on Passport Prime, keep it connected, then pair again.",
      );
    } else {
      setPair("err", `Pairing failed: ${e?.message || e}`);
    }
  }
});

$("forget").addEventListener("click", async () => {
  try {
    await resetUsbTransport();
    const granted = await navigator.usb.getDevices();
    for (const d of granted) {
      try { await d.forget(); } catch {}
    }
    await resetUsbTransport();
    await refreshPairStatus();
  } catch (e) {
    setPair("err", `Forget pairing failed: ${e?.message || e}`);
  }
});

const cfg = await chrome.storage.local.get(["transportKind", "wsServerUrl", "developerMode"]);
$("developer-mode").checked = !!cfg.developerMode;
$("transport-dev-controls").classList.toggle("hidden", !cfg.developerMode);
$("sim-mode").checked = cfg.developerMode && cfg.transportKind === "ws";
$("ws-url").value = cfg.wsServerUrl || "ws://127.0.0.1:9876";

$("developer-mode").addEventListener("change", async (e) => {
  const enabled = e.target.checked;
  $("transport-dev-controls").classList.toggle("hidden", !enabled);
  await chrome.storage.local.set({
    developerMode: enabled,
    transportKind: enabled && $("sim-mode").checked ? "ws" : "webusb",
  });
});

$("sim-mode").addEventListener("change", async (e) => {
  if (!$("developer-mode").checked) {
    e.target.checked = false;
    return;
  }
  await chrome.storage.local.set({
    transportKind: e.target.checked ? "ws" : "webusb",
  });
});
function isLoopbackWs(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "ws:") return false;
    return u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]";
  } catch {
    return false;
  }
}

$("ws-url").addEventListener("change", async (e) => {
  const value = e.target.value;
  if (!isLoopbackWs(value)) {
    e.target.value = "ws://127.0.0.1:9876";
    setPair("err", "Simulator URL must be a loopback ws:// address");
    return;
  }
  await chrome.storage.local.set({ wsServerUrl: value });
});

await refreshPairStatus();
