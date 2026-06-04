// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

// WebUSB transport. Speaks newline-delimited JSON to the Vaults Bridge
// app on Passport Prime, which exposes a vendor-class USB interface
// (class/subclass/protocol = 0xFF/0xFF/0xFF) with two 64-byte Interrupt
// endpoints plus WebUSB + MS OS 2.0 Platform Capability descriptors.
// Mirrors nostr-signer/browser-extension-1.3/webusb-transport.js for
// transport plumbing; method surface differs.

const REQUEST_TIMEOUT_MS = 5 * 60 * 1000; // allow for on-device approval tap
const PROBE_TIMEOUT_MS = 1500;
const MAX_LINE_BYTES = 16 * 1024;
const DEBUG_USB = false;

function debugUsb(...args) {
  if (DEBUG_USB) console.log(...args);
}

const DEVICE_FILTER = {
  classCode: 0xff,
  subclassCode: 0xff,
  protocolCode: 0xff,
};

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
  }

  async connect() {
    const granted = await navigator.usb.getDevices();
    if (granted.length === 0) {
      throw new Error("No Passport Prime paired yet");
    }
    const failures = [];
    for (const d of granted) {
      const { ok, reason } = await this._tryOpen(d);
      if (ok) return;
      failures.push(reason);
    }
    // Prefer the most informative single reason — concatenating reasons
    // across multiple paired devices is overwhelming and almost never
    // useful (users typically have one Prime paired).
    throw new Error(failures[0] || "Couldn't connect to Passport Prime");
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

    // KeyOS exposes more than one vendor-class interface (one is the
    // boot-time usb-debug, others are runtime-registered apps). Try
    // every matching interface in turn; the one that answers `ping`
    // is Vaults Bridge.
    const candidates = [];
    for (const iface of device.configuration.interfaces) {
      const alt = iface.alternate;
      if (
        alt.interfaceClass === DEVICE_FILTER.classCode &&
        alt.interfaceSubclass === DEVICE_FILTER.subclassCode &&
        alt.interfaceProtocol === DEVICE_FILTER.protocolCode
      ) {
        const inEp = alt.endpoints.find((e) => e.direction === "in");
        const outEp = alt.endpoints.find((e) => e.direction === "out");
        if (inEp && outEp) {
          candidates.push({
            ifaceNumber: iface.interfaceNumber,
            inEp: inEp.endpointNumber,
            outEp: outEp.endpointNumber,
          });
        }
      }
    }
    if (candidates.length === 0) {
      try { await device.close(); } catch {}
      return { ok: false, reason: "Open the Passwords app on your Passport Prime, then click the extension again." };
    }
    debugUsb(
      "[vaults-bridge/webusb] probing",
      candidates.length,
      "vendor-class interface(s):",
      candidates.map((c) => c.ifaceNumber),
    );

    const probeFailures = [];
    for (const c of candidates) {
      try {
        await device.claimInterface(c.ifaceNumber);
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
      reason: "Open the Passwords app on your Passport Prime, then click the extension again.",
    };
  }

  async _tearDown() {
    this.readAbort = true;
    try {
      if (this.device && this.ifaceNumber !== null) {
        await this.device.releaseInterface(this.ifaceNumber);
      }
    } catch {}
    try {
      if (this.device && this.device.opened) await this.device.close();
    } catch {}
    this.device = null;
    this.ifaceNumber = null;
    this.inEp = null;
    this.outEp = null;
    this.lineBuffer = "";
    for (const [, entry] of this.pending) {
      entry.reject({ code: 99, message: "disconnected" });
    }
    this.pending.clear();
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