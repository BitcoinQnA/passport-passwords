// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// Offscreen document. Hosts the WebUSB transport on behalf of the
// service worker (background.js). navigator.usb is not exposed in MV3
// service workers, so we proxy: background forwards RPC requests to
// this document via chrome.runtime.sendMessage, we do the actual USB
// I/O, and we return the result.

import { WebUsbTransport } from "./webusb-transport.js";

console.log("[vaults-bridge/offscreen] loaded");

const transport = new WebUsbTransport();
console.log("[vaults-bridge/offscreen] transport instantiated");

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== "offscreen-usb") return;
  console.log("[vaults-bridge/offscreen] msg:", msg.type, msg.method);
  (async () => {
    try {
      if (msg.type === "connect") {
        await transport.connect();
        sendResponse({ ok: true });
      } else if (msg.type === "disconnect") {
        await transport.disconnect();
        sendResponse({ ok: true });
      } else if (msg.type === "rpc") {
        const result = await transport.rpc(msg.method, msg.params);
        console.log("[vaults-bridge/offscreen] rpc result", msg.method, result);
        sendResponse({ ok: true, result });
      } else {
        sendResponse({ ok: false, error: `unknown type ${msg.type}` });
      }
    } catch (e) {
      console.warn("[vaults-bridge/offscreen] rpc error", e);
      sendResponse({
        ok: false,
        error: { code: 99, message: String(e?.message || e) },
      });
    }
  })();
  return true;
});

console.log("[vaults-bridge/offscreen] listener registered");