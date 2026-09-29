# Architecture diagrams

Each diagram has its own folder:

| Folder | Diagram |
|---|---|
| [`sign-in/`](sign-in/) | Sign-in through the OIDC provider and personal token issuance |
| [`request-flow/`](request-flow/) | Calling an MCP server (token exchange) and an HTTP API (no upstream credential) |
| [`token-exchange/`](token-exchange/) | Token lookup, policy check, upstream secret, and the rejection path |

A folder contains:

- `<name>.sequence.json`: the **source**. Edit this file, never the SVGs.
- `<name>-light.svg` and `<name>-dark.svg`: rendered output. The READMEs
  embed them with `<picture>`, so GitHub picks the variant that matches the
  reader's theme.

## Regenerating

The sources are sequence specs for [archify](https://github.com/tt-a1i/archify).
To regenerate a diagram:

1. Validate the source: `archify validate sequence <name>.sequence.json --quality showcase`.
2. Render it: `archify deliver sequence <name>.sequence.json <name>.html --quality showcase`.
3. Export the diagram's `<svg>` from that HTML once per theme (light and dark),
   with the computed styles inlined. The SVG must stand alone: no CSS
   variables, no scripts, no external references. GitHub renders SVGs as
   images, so anything else is lost.
