// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const $ = (id) => document.getElementById(id);

const DEVICE_FILTER = {
  classCode: 0xff,
  subclassCode: 0xff,
  protocolCode: 0xff,
};

function setPair(state, text) {
  const dot = $("pair-dot");
  dot.classList.remove("ok", "err");
  if (state === "ok") dot.classList.add("ok");
  else if (state === "err") dot.classList.add("err");
  $("pair-status").textContent = text;
}

async function refreshPairStatus() {
  try {
    const granted = await navigator.usb.getDevices();
    if (granted.length === 0) {
      setPair("idle", "Not connected");
      return;
    }
    const names = granted.map((d) => d.productName || `${d.vendorId}:${d.productId}`);
    setPair("ok", `Connected: ${names.join(", ")}`);
  } catch (e) {
    setPair("err", `WebUSB unavailable: ${e?.message || e}`);
  }
}

$("pair").addEventListener("click", async () => {
  try {
    await navigator.usb.requestDevice({ filters: [DEVICE_FILTER] });
    await refreshPairStatus();
  } catch (e) {
    if (e?.name !== "NotFoundError") {
      setPair("err", `Connect failed: ${e?.message || e}`);
    }
  }
});

$("forget").addEventListener("click", async () => {
  try {
    const granted = await navigator.usb.getDevices();
    for (const d of granted) {
      try { await d.forget(); } catch {}
    }
    await refreshPairStatus();
  } catch (e) {
    setPair("err", `Forget failed: ${e?.message || e}`);
  }
});

const cfg = await chrome.storage.local.get(["transportKind", "wsServerUrl"]);
$("sim-mode").checked = cfg.transportKind === "ws";
$("ws-url").value = cfg.wsServerUrl || "ws://127.0.0.1:9876";

$("sim-mode").addEventListener("change", async (e) => {
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