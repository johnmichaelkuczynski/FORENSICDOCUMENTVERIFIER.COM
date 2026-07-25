---
name: pdf-parse version constraint
description: Why pdf-parse v1 must be used instead of v2 in Node.js environments
---

Always use `pdf-parse@1` — NOT v2.

**Why:** pdf-parse v2 bundles pdfjs-dist, which requires `DOMMatrix` (a browser DOM API). Node.js 24 does not polyfill `DOMMatrix`, so the server crashes on startup with `ReferenceError: DOMMatrix is not defined`. pdf-parse v1 is self-contained and works in pure Node.js without browser globals.

**How to apply:** When adding or upgrading the pdf-parse dependency in any server-side package, pin to `^1.x`. If the firewall offers v2, explicitly request `pdf-parse@1`.
