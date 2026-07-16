// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

const { createServer } = require("node:http");
const { readFile } = require("node:fs/promises");
const { extname, join, normalize } = require("node:path");

const root = __dirname;
const host = process.env.DEMO_HOST || "127.0.0.1";

const sites = [
  { name: "Foogle", dir: "foogle", port: Number(process.env.FOOGLE_PORT || 8081) },
  { name: "Y", dir: "y", port: Number(process.env.Y_PORT || 8082) },
];

const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
]);

function makeServer(site) {
  const siteRoot = normalize(join(root, site.dir));
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url || "/", `http://${host}:${site.port}`);
      const requestedPath = decodeURIComponent(url.pathname);
      const relative = requestedPath === "/" ? "index.html" : requestedPath.slice(1);
      const filePath = normalize(join(siteRoot, relative));

      if (!filePath.startsWith(siteRoot)) {
        res.writeHead(403).end("Forbidden");
        return;
      }

      const body = await readFile(filePath);
      res.writeHead(200, {
        "content-type": types.get(extname(filePath)) || "application/octet-stream",
        "cache-control": "no-store",
      });
      res.end(body);
    } catch {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("Not found");
    }
  });
}

for (const site of sites) {
  makeServer(site).listen(site.port, host, () => {
    console.log(`${site.name}: http://${host}:${site.port}`);
  });
}
