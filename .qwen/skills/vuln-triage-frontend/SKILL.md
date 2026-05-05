---
name: vuln-triage-frontend
description: Triage methodology for AngularJS (1.x) frontend findings. CWE-specific signal checklists, AngularJS-specific FP traps (SCE auto-escaping, ng-bind, sandbox removal), and template/controller data-flow tracing. Loaded by vuln-triage when a finding's locations point to .js / .html files. Do not invoke standalone — sub-skill driven by vuln-triage.
---

# Frontend triage — AngularJS 1.x

This skill refines step 4 of `vuln-triage` for AngularJS code. Same hard rules: research only via code-index, never call admin tools, never write code, only `update_triage_result`.

## Locating the entry point

Frontend "entry points" (taint sources) — places where untrusted data enters the app:

- **HTTP responses** — `$http.get/post`, `$resource`. The body comes from the server; treat as **semi-trusted** (trusted vs. cross-tenant attackers, untrusted vs. data-injection through other tenants/admins).
- **Route params** — `$routeParams`, `$stateParams` (ui-router), `$location.search()`, `$location.hash()`. **Fully attacker-controlled** (URL).
- **`window.location` / `document.referrer`** — attacker-controlled.
- **`postMessage` listeners** — `$window.addEventListener('message', ...)`. Attacker-controlled if no `event.origin` allowlist.
- **`localStorage` / `sessionStorage`** — trust depends on what writes there. If anything ever wrote attacker-controlled content, the read is tainted.
- **Form inputs / `ng-model`** — user-controlled in the same browser session; usually tainted only for the user themselves (not cross-user) **unless** it ends up rendered for someone else (stored XSS).

Use `code-index` to find the controller/directive/service that consumes the source, then trace forward to a sink.

## CWE checklist — AngularJS

### CWE-79 — Cross-Site Scripting

AngularJS has **Strict Contextual Escaping (SCE)** enabled by default. Most string interpolation is auto-escaped. The narrow set of dangerous sinks:

- **`$sce.trustAsHtml(userInput)`** — bypasses SCE. Confirm if input is tainted; reject only if the argument is a constant or a server-rendered template that the server controls completely.
- **`ng-bind-html="expr"`** — renders HTML. Safe **only if** `expr` is constant/server-controlled OR has been sanitised by `$sanitize` (the `ngSanitize` module must be loaded). Confirm if user-controllable data flows in without `$sanitize`.
- **`$compile(htmlString)(scope)`** — compiles arbitrary template. Almost always confirmed if `htmlString` is user-controllable (allows `{{}}` expression injection too, not just HTML).
- **`element.html(...)`** / jQuery `.html()` / `innerHTML` — outside Angular's sanitisation. Confirm if user-controllable.
- **`$sce.trustAsResourceUrl` / `$sce.trustAsJs`** — same FP/TP rules as `trustAsHtml`.
- **Dynamic templates** — `templateUrl: function(){ return userPath; }`. Confirm if attacker controls `userPath` (template injection → arbitrary HTML/JS).

**Auto-escaped (typical FP):**
- `{{ expr }}` interpolation → escaped, **safe**.
- `ng-bind="expr"` → escaped, **safe**.
- `ng-href`, `ng-src` → URL context, escaped against `javascript:` by default in modern AngularJS (1.5+) when SCE is on.

**Edge-case FPs / TPs:**
- `$sceProvider.enabled(false)` in app config — SCE is **disabled globally**. All bindings become potentially dangerous; re-evaluate every XSS finding as more likely confirmed.
- `$compileProvider.aHrefSanitizationWhitelist(/.*/)` or `imgSrcSanitizationWhitelist(/.*/)` — safety net removed; `javascript:` URLs reachable. Confirm related findings.
- AngularJS expression sandbox was **removed in 1.6** (and was never a security boundary anyway). Don't reject XSS just because "expressions are sandboxed" — they're not.

### CWE-601 — Open Redirect
- **Sinks:** `$location.url(userParam)`, `$window.location.href = userParam`, `<a ng-href="{{userUrl}}">` followed by automated click.
- **Confirm if:** target URL is user-controllable and not validated against an allowlist of paths/hosts.
- **Reject if:** redirect is to a path-only allowlist (`/dashboard`, `/login`) OR full URL is checked against an explicit host allowlist.
- **FP trap:** `$location.path('/' + userParam)` is **still** open redirect — `userParam = '/evil.com'` produces `//evil.com` (protocol-relative URL). Don't reject unless there's a regex anchoring to a known segment.

### CWE-915 — Prototype Pollution / Mass Assignment
- **Sinks:** `angular.merge(target, untrusted)`, `angular.extend(target, untrusted)`, lodash `_.merge`/`_.set` with user data, `Object.assign({}, untrustedJson)` (only `__proto__` direct key risk; lodash older versions are worse).
- **Confirm if:** untrusted JSON is merged into an object that is later used in security-sensitive logic (auth flags, route guards, `$http` config defaults).
- **Reject if:** merge target is a fresh object with explicit fields copied (whitelist), OR lodash version ≥ 4.17.12 with proven prototype-pollution patches AND no `_.set` with user-controlled path.

### CWE-200 — Sensitive Data Exposure
- **Confirm if:** auth tokens / PII written to `localStorage`, `sessionStorage`, or `console.log` in production code paths.
- **Reject if:** debug logging is gated by `if (DEBUG)` or removed by build-time tree-shaking — verify with `code-index` the gating constant is set false in prod config.
- **Token-in-localStorage** is a classic XSS-amplifier finding: rejected only if the app provably has no `$sce`-bypassing sinks (see XSS section). In practice, it stays **confirmed** unless the team has deliberately accepted the trade-off.

### CWE-352 — CSRF (frontend side)
- AngularJS's `$http` auto-sets `X-XSRF-TOKEN` from the `XSRF-TOKEN` cookie. SAST findings flagging missing CSRF on AngularJS forms are often FP **if** the backend reads `X-XSRF-TOKEN` (verify with the corresponding backend symbol via code-index).
- Confirm if backend ignores `X-XSRF-TOKEN` and relies on cookie-only auth.

### CWE-1004 — Cookie without `HttpOnly` (where set client-side)
- AngularJS `$cookies` — confirm if auth tokens are stored via `$cookies.put(...)` (always lacks `HttpOnly` from JS).
- Reject if `$cookies` is used only for non-sensitive UI state.

## AngularJS framework FP traps — common false positives

- **`{{ }}` interpolation** auto-escapes. XSS findings on `{{userName}}` → almost always FP.
- **`ng-bind`** auto-escapes. Same as above.
- **`ng-bind-html` with `$sanitize`** — load `ngSanitize` module → safe rendering of HTML subset. Confirm only if `ngSanitize` is **not** in `angular.module(...)` deps.
- **`$sce.trustAsHtml(staticTemplate)`** where `staticTemplate` is a string literal or `require`'d template file — safe (developer controls content).
- **Server-rendered constants pulled via `$http` from same-origin trusted endpoint** — semi-trusted; usually FP for direct rendering.
- **AngularJS expression "sandbox"** — historically present, removed in 1.6, was never a security boundary. Do **not** treat sandbox as a defence in either direction. Don't reject `$compile`-of-user-input on "but it's sandboxed".

## Tracing data flow with code-index

1. From `locations` (file:line), use `find_files` + `get_symbol_body` to read the controller/directive containing the sink.
2. Identify the bound expression / argument variable feeding the sink.
3. Backtrack: where is that variable assigned? `code-index` symbol search for assignments / function returns.
4. Continue backtracking until you reach one of:
   - A constant / module-loaded template (→ likely safe; reject).
   - An `$http` / `$resource` response (→ semi-trusted; depends on backend).
   - A `$routeParams` / `$location` / `$window.name` / `event.data` (→ tainted; confirm unless guarded).
5. **Note guards on the path:** `$sanitize`, manual whitelist regex, type checks (`angular.isString`), DOMPurify, server-side encoding before transmission.

## Output

Your reasoning must name:
- **Taint source** (e.g. `$routeParams.q` in `SearchController` line N).
- **Sink** (e.g. `$sce.trustAsHtml` in `searchResults.html` directive line M).
- **Guards** (`$sanitize` present? `ngSanitize` module loaded? URL allowlist?).
- **Decisive fact** (no sanitisation between route param and `trustAsHtml` → confirmed; or `$sanitize` invocation on line K → rejected).

Then call `update_triage_result` with the verdict.
