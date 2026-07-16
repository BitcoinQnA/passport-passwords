// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// WebUSB transport. Speaks newline-delimited JSON to the Vaults Bridge
// app on Passport Prime, which exposes a vendor-class USB interface
// (class/subclass/protocol = 0xFF/0x50/0x01) with two 64-byte Interrupt
// endpoints plus WebUSB + MS OS 2.0 Platform Capability descriptors.
// Mirrors nostr-signer/browser-extension-1.3/webusb-transport.js for
// transport plumbing; method surface differs.

const REQUEST_TIMEOUT_MS = 5 * 60 * 1000; // allow for on-device approval tap
const PROBE_TIMEOUT_MS = 1500;
const CONNECT_RETRY_WINDOW_MS = 5000;
const CONNECT_RETRY_DELAY_MS = 250;
const MAX_LINE_BYTES = 16 * 1024;
const DEBUG_USB = false;

function debugUsb(...args) {
  if (DEBUG_USB) console.log(...args);
}

const DEVICE_FILTER = {
  classCode: 0xff,
  subclassCode: 0x50,
  protocolCode: 0x01,
};

const FOUNDATION_PASSPORT_FILTER = {
  vendorId: 0x1307,
  productId: 0x0165,
};

function isLikelyPassport(device) {
  return (
    (device.vendorId === FOUNDATION_PASSPORT_FILTER.vendorId &&
      device.productId === FOUNDATION_PASSPORT_FILTER.productId) ||
    /passport/i.test(device.productName || "")
  );
}

function hexByte(value) {
  return `0x${Number(value || 0).toString(16).padStart(2, "0")}`;
}

function endpointSummary(endpoint) {
  return `${endpoint.direction}:${endpoint.type || "?"}:${endpoint.endpointNumber}`;
}

function collectInterfaceCandidates(device) {
  const candidates = [];
  const descriptions = [];
  const interfaces = device.configuration?.interfaces || [];
  for (const iface of interfaces) {
    const alternates = iface.alternates?.length ? iface.alternates : [iface.alternate].filter(Boolean);
    for (const alt of alternates) {
      const endpoints = alt.endpoints || [];
      descriptions.push(
        `if${iface.interfaceNumber}/alt${alt.alternateSetting ?? "?"} ` +
        `${hexByte(alt.interfaceClass)}/${hexByte(alt.interfaceSubclass)}/${hexByte(alt.interfaceProtocol)} ` +
        `eps=${endpoints.map(endpointSummary).join(",") || "none"}`,
      );

      const inEp = endpoints.find((e) => e.direction === "in" && e.type === "interrupt") ||
        endpoints.find((e) => e.direction === "in");
      const outEp = endpoints.find((e) => e.direction === "out" && e.type === "interrupt") ||
        endpoints.find((e) => e.direction === "out");
      if (!inEp || !outEp) continue;

      const exact =
        alt.interfaceClass === DEVICE_FILTER.classCode &&
        alt.interfaceSubclass === DEVICE_FILTER.subclassCode &&
        alt.interfaceProtocol === DEVICE_FILTER.protocolCode;
      if (!exact) continue;
      candidates.push({
        ifaceNumber: iface.interfaceNumber,
        alternateSetting: alt.alternateSetting,
        inEp: inEp.endpointNumber,
        outEp: outEp.endpointNumber,
        descriptor:
          `if${iface.interfaceNumber}/alt${alt.alternateSetting ?? "?"} ` +
          `${hexByte(alt.interfaceClass)}/${hexByte(alt.interfaceSubclass)}/${hexByte(alt.interfaceProtocol)} ` +
          `IN=${inEp.endpointNumber} OUT=${outEp.endpointNumber}`,
      });
    }
  }
  candidates.sort((a, b) => a.ifaceNumber - b.ifaceNumber);
  return { candidates, descriptions };
}

export class WebUsbTransport {
  constructor() {
    this.device = null;
    this.ifaceNumber = null;
    this.inEp = null;
    this.outEp = null;
    this.readLoop = null;
    this.lineBuffer = "";
    this.pending = new Map();
    this.readAbort = false;
    this.connectPromise = null;
    this.teardownPromise = null;

    navigator.usb.addEventListener("disconnect", (event) => {
      if (event.device === this.device) {
        this._tearDown().catch(() => {});
      }
    });
  }

  async connect() {
    if (this.device) return;
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = this._connectWithRetry();
    try {
      await this.connectPromise;
    } finally {
      this.connectPromise = null;
    }
  }

  async _connectWithRetry() {
    const deadline = Date.now() + CONNECT_RETRY_WINDOW_MS;
    let sawPassport = false;
    let lastFailure = "Couldn't connect to Passport Prime";

    while (true) {
      const granted = await navigator.usb.getDevices();
      const devices = granted.filter(isLikelyPassport);
      if (devices.length > 0) sawPassport = true;
      if (!sawPassport && devices.length === 0) {
        throw new Error("No Passport Prime paired yet");
      }

      for (const device of devices) {
        const { ok, reason } = await this._tryOpen(device);
        if (ok) return;
        lastFailure = reason || lastFailure;
      }

      if (Date.now() >= deadline) break;
      await sleep(CONNECT_RETRY_DELAY_MS);
    }

    // A foreground app launch briefly removes and recreates its dynamic USB
    // interface. Retrying here absorbs that normal re-enumeration window;
    // RPCs themselves are never replayed automatically.
    throw new Error(lastFailure);
  }

  async _tryOpen(device) {
    try {
      if (!device.opened) await device.open();
      if (device.configuration === null) await device.selectConfiguration(1);
    } catch (e) {
      const raw = String(e?.message || e);
      console.warn("[vaults-bridge/webusb] open failed:", raw);
      const friendly = /disconnected/i.test(raw)
        ? "Passport Prime disconnected. Reconnect it via USB and try again."
        : "Couldn't open Passport Prime. Unplug and replug it, then try again.";
      return { ok: false, reason: friendly };
    }

    // Claim only the Passwords interface. Other Prime apps and USB debug
    // surfaces use different vendor-class identities and different protocols.
    const { candidates, descriptions } = collectInterfaceCandidates(device);
    if (candidates.length === 0) {
      try { await device.close(); } catch {}
      console.warn(
        "[vaults-bridge/webusb] Passport paired but no usable app interface was visible:",
        descriptions,
      );
      return {
        ok: false,
        reason:
          "Passport Prime is paired, but the Passwords USB interface is not available. " +
          "Keep Passwords open, unplug and reconnect USB, then try again.",
      };
    }
    debugUsb(
      "[vaults-bridge/webusb] probing",
      candidates.map((c) => c.descriptor),
    );

    const probeFailures = [];
    for (const c of candidates) {
      try {
        await device.claimInterface(c.ifaceNumber);
        if (typeof c.alternateSetting === "number") {
          await device.selectAlternateInterface(c.ifaceNumber, c.alternateSetting);
        }
      } catch (e) {
        probeFailures.push(`iface ${c.ifaceNumber} claim: ${e?.message || e}`);
        continue;
      }
      this.device = device;
      this.ifaceNumber = c.ifaceNumber;
      this.inEp = c.inEp;
      this.outEp = c.outEp;
      this.readAbort = false;
      this.lineBuffer = "";
      this.readLoop = this._readLoop();
      debugUsb(
        "[vaults-bridge/webusb] claimed iface",
        c.ifaceNumber,
        "ep IN=",
        c.inEp,
        "ep OUT=",
        c.outEp,
      );
      try {
        await this._rawRpc("ping", null, PROBE_TIMEOUT_MS);
        debugUsb("[vaults-bridge/webusb] probe ok on iface", c.ifaceNumber);
        return { ok: true };
      } catch (e) {
        probeFailures.push(`iface ${c.ifaceNumber} ping: ${e?.message || e}`);
        // Tear down THIS attempt (release iface, stop read loop) but
        // keep the device open so we can try the next candidate.
        this.readAbort = true;
        try {
          await device.releaseInterface(c.ifaceNumber);
        } catch {}
        this.device = null;
        this.ifaceNumber = null;
        this.inEp = null;
        this.outEp = null;
        this.lineBuffer = "";
        for (const [, entry] of this.pending) {
          entry.reject({ code: 99, message: "probe failed" });
        }
        this.pending.clear();
      }
    }
    try { await device.close(); } catch {}
    console.warn("[vaults-bridge/webusb] all candidate interfaces failed probe:", probeFailures);
    return {
      ok: false,
      reason:
        "Passport Prime is paired, but the Passwords USB interface did not respond. " +
        "Keep Passwords open, unplug and reconnect USB, then try again.",
    };
  }

  async _tearDown() {
    if (this.teardownPromise) return this.teardownPromise;
    const device = this.device;
    const ifaceNumber = this.ifaceNumber;
    this.readAbort = true;
    this.device = null;
    this.ifaceNumber = null;
    this.inEp = null;
    this.outEp = null;
    this.lineBuffer = "";
    for (const [, entry] of this.pending) {
      entry.reject({ code: 99, message: "disconnected" });
    }
    this.pending.clear();
    this.teardownPromise = (async () => {
      try {
        if (device && ifaceNumber !== null) {
          await device.releaseInterface(ifaceNumber);
        }
      } catch {}
      try {
        if (device?.opened) await device.close();
      } catch {}
    })();
    try {
      await this.teardownPromise;
    } finally {
      this.teardownPromise = null;
    }
  }

  async disconnect() {
    await this._tearDown();
  }

  async _readLoop() {
    const dec = new TextDecoder("utf-8");
    while (!this.readAbort && this.device) {
      try {
        const r = await this.device.transferIn(this.inEp, 64);
        debugUsb(
          "[vaults-bridge/webusb] transferIn",
          r.status,
          r.data ? r.data.byteLength : 0,
          "bytes",
        );
        if (r.status !== "ok") continue;
        if (!r.data || r.data.byteLength === 0) continue;
        this.lineBuffer += dec.decode(r.data, { stream: true });
        if (this.lineBuffer.length > MAX_LINE_BYTES) {
          // A line longer than the cap means the device is misbehaving
          // (or hostile). Drop the buffer, fail any pending RPCs, and
          // tear down so the next call re-opens cleanly.
          this.lineBuffer = "";
          for (const [, entry] of this.pending) {
            entry.reject({ code: 99, message: "transport overflow" });
          }
          this.pending.clear();
          await this._tearDown();
          break;
        }
        let idx;
        while ((idx = this.lineBuffer.indexOf("\n")) >= 0) {
          const line = this.lineBuffer.slice(0, idx);
          this.lineBuffer = this.lineBuffer.slice(idx + 1);
          if (!line.trim()) continue;
          let msg;
          try {
            msg = JSON.parse(line);
          } catch {
            continue;
          }
          const entry = this.pending.get(msg.id);
          if (!entry) continue;
          this.pending.delete(msg.id);
          if (msg.error) entry.reject(msg.error);
          else entry.resolve(msg.result);
        }
      } catch (e) {
        if (this.readAbort) break;
        for (const [, entry] of this.pending) entry.reject({ code: 99, message: String(e) });
        this.pending.clear();
        await this._tearDown();
        break;
      }
    }
  }

  async _writeLine(json) {
    const enc = new TextEncoder();
    const bytes = enc.encode(json + "\n");
    debugUsb(
      "[vaults-bridge/webusb] _writeLine",
      bytes.byteLength,
      "bytes to ep OUT=",
      this.outEp,
      ":",
      json.slice(0, 80),
    );
    // Chunk into 64-byte writes to match the interrupt endpoint max.
    const CHUNK = 64;
    for (let off = 0; off < bytes.byteLength; off += CHUNK) {
      const slice = bytes.slice(off, Math.min(off + CHUNK, bytes.byteLength));
      const r = await this.device.transferOut(this.outEp, slice);
      debugUsb(
        "[vaults-bridge/webusb] transferOut chunk",
        slice.byteLength,
        "status=",
        r.status,
        "bytesWritten=",
        r.bytesWritten,
      );
      if (r.status !== "ok") throw new Error(`transferOut ${r.status}`);
    }
  }

  async _rawRpc(method, params, timeoutMs = REQUEST_TIMEOUT_MS) {
    if (!this.device) throw new Error("not connected");
    const id = uid();
    const req = { id, method };
    // Only attach `params` when there's something to send. Unit variants
    // on the device side (like `ping`) reject `params: {}` with
    // `expected unit variant`. Empty objects come from background.js
    // defaulting `msg.params || {}` for messages that have no params.
    if (
      params != null &&
      (typeof params !== "object" || Object.keys(params).length > 0)
    ) {
      req.params = params;
    }
    const json = JSON.stringify(req);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`timeout: ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(t); resolve(v); },
        reject: (e) => { clearTimeout(t); reject(e); },
      });
      this._writeLine(json).catch((e) => {
        clearTimeout(t);
        if (this.pending.delete(id)) reject(e);
        this._tearDown().catch(() => {});
      });
    });
  }

  async rpc(method, params) {
    if (!this.device) await this.connect();
    return this._rawRpc(method, params);
  }
}

function uid() {
  const b = new Uint8Array(8);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
