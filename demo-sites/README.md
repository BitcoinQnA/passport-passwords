<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Demo Login Sites

Two local-only demo pages for filming and testing the browser extension without
using a real website login form.

- Foogle: `http://127.0.0.1:8081`
- Y: `http://127.0.0.1:8082`

Run both:

```bash
node demo-sites/serve.js
```

Suggested Passport entries:

| Label | Website | Username |
|---|---|---|
| Foogle | `http://127.0.0.1:8081` | `alex@foogle.test` |
| Y | `http://127.0.0.1:8082` | `@demo` |

Use any fake password. These pages prevent normal form submission and do not
send credentials to any server.
