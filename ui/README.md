# Web UI

The controller ships this static web client at `/`. It uses only the documented
public API and requires no Node.js runtime in production. The HTML, JavaScript,
and stylesheet are embedded in `mcloving-controller`; `/openapi.json` exposes
the API contract used by the client.
