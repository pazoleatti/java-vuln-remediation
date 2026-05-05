---
name: vuln-triage-backend
description: Triage methodology for Spring/Groovy backend findings. CWE-specific signal checklists, Spring framework FP traps, and Groovy-specific exploitation surfaces. Loaded by vuln-triage when a finding's locations point to .java / .groovy / .kt / .gradle files. Do not invoke standalone — it is a sub-skill driven by vuln-triage.
---

# Backend triage — Spring + Groovy

This skill refines step 4 ("Investigate via code-index") of `vuln-triage` for Spring/Groovy code. Same rules apply: research only via code-index, never call admin tools, never write code, only `update_triage_result`.

## Locating the entry point

Spring entry points (taint sources) — work backward from the sink to find one of these:

- `@RestController`, `@Controller`, `@RequestMapping`, `@GetMapping`, `@PostMapping`, etc. — HTTP request handlers. Method parameters annotated `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`, `@ModelAttribute` are tainted by default.
- `@MessageMapping`, `@KafkaListener`, `@JmsListener`, `@RabbitListener` — message consumers; payload is tainted.
- `@Scheduled` — **not** an entry point unless config is user-controllable.
- Servlet `Filter`, `HandlerInterceptor` — request-touching code; check what they pass downstream.
- Groovy: scripts loaded at runtime via `GroovyShell`, `GroovyScriptEngine`, `ScriptEngineManager` — the script body itself may be the entry point.

Use `code-index` symbol search to find the controller method, then `get_symbol_body` to read it. Walk from there: request param → service call → repo call → sink.

## CWE checklist — what to inspect for each class

### CWE-89 — SQL Injection
- **Sinks:** `JdbcTemplate.query/queryForObject/update`, `NamedParameterJdbcTemplate`, native `EntityManager.createNativeQuery`, JPA `@Query(nativeQuery = true)`, Groovy `Sql.rows/firstRow`.
- **Confirm if:** SQL string is built via concatenation / `String.format` / Groovy GString interpolation with user data.
- **Reject if:** parameters bind via `?` placeholders or `:named` params; or the query is a Spring Data **derived** method (`findByXxx`) — those are always parameterised; or `@Query` without `nativeQuery=true` (JPQL is parsed, not concatenated).
- **FP trap:** Spring Data JPA derived queries flagged as SQLi → almost always FP.

### CWE-502 — Insecure Deserialization
- **Sinks:** `ObjectInputStream.readObject`, Jackson with `enableDefaultTyping`/`activateDefaultTyping`, XStream without allowlist, Kryo without registered classes, SnakeYAML `new Yaml().load(...)` (use `SafeConstructor`).
- **Confirm if:** input stream is reachable from HTTP/MQ payload AND no allowlist/type-check is present.
- **Reject if:** Jackson uses default config (no default typing) and only DTOs are deserialized; or XStream has explicit `allowTypes`/`allowTypeHierarchy`.
- **Groovy:** `ObjectInputStream` with custom `resolveClass` allowlist → safe.

### CWE-918 — SSRF
- **Sinks:** `RestTemplate.exchange/getForObject`, `WebClient`, `HttpClient`, `URL.openConnection`, `Unirest`, Groovy `URL#getText`.
- **Confirm if:** URL/host is user-controllable and not validated against an allowlist of hosts/schemes.
- **Reject if:** URL is constructed from a fixed host + user-supplied path (and path is encoded), OR there's an allowlist/regex check before the call.
- **Common partial fix (still confirm):** scheme check (`http`/`https`) without host allowlist — leaves cloud-metadata SSRF (`169.254.169.254`).

### CWE-94 / CWE-913 / CWE-829 — Code Injection & Untrusted Dynamic Code
- **Sinks (one-shot eval):** `SpelExpressionParser.parseExpression`, `@PreAuthorize` with concatenated strings, `ScriptEngine.eval`, Groovy `Eval.me/x/xy`, `GroovyShell.evaluate`, `Binding`+`GroovyShell.evaluate`.
- **Sinks (runtime script loading) — see dedicated section below:** `GroovyClassLoader.parseClass`, `GroovyShell.parse`, `GroovyScriptEngine`, `GroovyCodeSource`, `ScriptEngineManager.getEngineByName("groovy").eval`.
- **Confirm if:** the expression / script source contains user-controlled data, OR the script is loaded from a location any non-trusted principal can write to.
- **Reject if:** expression is a static literal / built only from trusted config, AND (for script loading) the source path is a build-time classpath resource with no override mechanism.
- **Groovy-specific:** `@CompileStatic` does **not** sandbox `Eval.me(userInput)` — the static compilation only applies to the calling code, not the dynamically evaluated script. Always confirm if user input reaches `Eval.me`.

### CWE-78 — OS Command Injection
- **Sinks:** `Runtime.exec(String)` (single-string form is dangerous), `ProcessBuilder` with shell wrappers (`sh -c`, `cmd /c`), Groovy `"...".execute()`.
- **Confirm if:** any element of the command/arguments is user-controlled with no allowlist.
- **Reject if:** `ProcessBuilder` uses `List<String>` form with hard-coded executable AND user data only in args that are not interpreted by a shell.
- **FP trap:** `Runtime.exec(String[])` array form is **safer** than `exec(String)` (no shell tokenisation), but still confirm if the executable name itself is user-controlled.

### CWE-22 — Path Traversal
- **Sinks:** `new File(userPath)`, `Files.copy/move/newInputStream`, `Paths.get(userPath)`, `MultipartFile.transferTo`.
- **Confirm if:** path joins user input without canonicalisation + base-dir check.
- **Reject if:** code calls `Path.normalize()` AND verifies the normalised path starts with an allowlisted base (`startsWith(baseDir)` after `toRealPath()`).
- **Common FP:** Spring `Resource` loaded via `ClassPathResource("static/" + name)` where `name` is allowlisted — check the allowlist.

### CWE-79 — Server-Side XSS (Thymeleaf / response rendering)
- **Sinks:** Thymeleaf `[(...)]` (unescaped) or `th:utext`, manual `response.getWriter().write(userInput)`, JSP `<%= %>` without `<c:out>`.
- **Confirm if:** unescaped output of user data.
- **Reject if:** default Thymeleaf `[[...]]` / `th:text` is used (auto-escaped).

### CWE-352 — CSRF
- **Confirm if:** state-changing endpoint (POST/PUT/DELETE) AND CSRF protection disabled (`csrf().disable()` in security config) AND no alternative protection (custom header check, SameSite cookie, JWT in non-cookie storage).
- **Reject if:** Spring Security CSRF is enabled (default) OR the endpoint is read-only (GET) OR auth is via `Authorization` header (not cookie) — token-bearer auth is inherently CSRF-resistant.

### CWE-200 / CWE-209 — Information Disclosure
- **Confirm if:** stack traces / SQL errors / internal paths are returned in HTTP response (typically `@ControllerAdvice` returning `ex.getMessage()` or no `@ExceptionHandler` at all).
- **Reject if:** there's a global exception handler that returns sanitized error responses.

### CWE-287 / CWE-285 — Auth & AuthZ
- Look for `@PreAuthorize`, `@Secured`, `@RolesAllowed`, programmatic `SecurityContextHolder` checks.
- **Confirm if:** state-changing or data-exposing endpoint has no method-level auth AND `SecurityFilterChain` does not cover this URL.
- **Reject if:** there's a chain-level rule (`authorizeHttpRequests().requestMatchers("/api/**").authenticated()`).
- **FP trap:** auth annotations on the **interface**, not the implementation, still apply if Spring proxies the bean — confirm by checking the interface too.

## Spring framework FP traps — common false positives

- **Bean-validation `@Valid` / `@Validated`** on a controller param + JSR-303 annotations on the DTO neutralise many "unvalidated input" findings.
- **Spring Data JPA repositories** never produce SQLi from derived methods or JPQL `@Query`. Native `@Query(nativeQuery=true)` is the only risky form.
- **Actuator endpoints** flagged as info disclosure are FP **if** Spring Security restricts them to admin role — verify in `SecurityFilterChain`.
- **`@RequestBody`** parsing rejects type mismatches and unknown fields (`FAIL_ON_UNKNOWN_PROPERTIES`) — so "untrusted data binding" findings often have a concrete DTO contract limiting exposure.

## Groovy-specific surfaces

- **Dynamic typing on Groovy controllers** means SAST may misidentify types — `get_symbol_body` and read carefully; the actual runtime type often ships through `def`.
- **`@CompileStatic` / `@TypeChecked`** at class or method level eliminates many dynamic-dispatch attack surfaces (e.g. method-handle injection) — note in reasoning if present.
- **GString interpolation** (`"${userInput}"`) compiles to a concatenation — for SQL/HTML/shell sinks this is **as dangerous as `+`**. Don't be fooled by the compact syntax.
- **Closure execution context** — `Closure.delegate` + `Closure.resolveStrategy = OWNER_FIRST` does not sandbox; if user input becomes a closure body via `Eval.me`, full JVM access is granted.
- **Groovy `MarkupBuilder`** auto-escapes attributes/text — XSS findings on it are typically FP.
- **`Sql.executeInsert(GString)`** is parameterised (Groovy converts `$var` placeholders to `?` bindings) — SQLi flagged on `groovy.sql.Sql` GString-form is usually FP. Concatenation (`Sql.execute("INSERT ... " + x)`) is real.

## Runtime Groovy scripting (production scripting engine)

This project loads `.groovy` scripts at runtime via `GroovyClassLoader` / `GroovyScriptEngine`. This is a **first-class attack surface**: anyone who can influence script bytes or script-source path can execute arbitrary code with full JVM privileges. Treat related CWE-94 / CWE-913 / CWE-829 findings as **high-priority** and bias toward **confirmed** unless a specific guard is verified.

### Working assumption — Groovy scripts have no sandbox

- The legacy Java `SecurityManager` is deprecated in JDK 17 and removed in JDK 24+. Do **not** count it as a control even if `policy` files exist.
- `SecureASTCustomizer` is **partial** at best — historically bypassed (AST transforms like `@groovy.transform.ASTTest`, dynamic dispatch tricks, reflection through `@Grab`), and only blocks specific AST nodes you list. **Reject only if the customizer is restrictive AND the threat model accepts residual bypass risk; a triager should generally still confirm.**
- Kohsuke's `groovy-sandbox` (used in Jenkins) is the most battle-tested option and even it has had escapes. Note its presence in reasoning, but do not treat it as decisive proof of safety.
- **Default conclusion: a loaded Groovy script has the same privileges as the JVM process** — filesystem, network, env vars, process spawn, all DataSource beans, all Spring beans accessible from `Binding`.

### Sinks to identify via code-index

Locate any of these via symbol search:

- `new GroovyClassLoader().parseClass(<source>)` — `<source>` may be `String`, `File`, `Reader`, `InputStream`, `GroovyCodeSource`, or a URL. Trace `<source>` to its origin.
- `new GroovyShell([binding]).parse(<source>)` / `.evaluate(<source>)` / `.run(<source>, ...)`.
- `new GroovyScriptEngine([roots])` — `roots` is an array of URL/path "script roots". File changes in those roots auto-reload. **Anyone who can write to a root = RCE.**
- `new GroovyCodeSource(scriptText, name, codeBase)` — the `codeBase` URL grants `CodeSource`-based permissions; user-controllable `codeBase` undermines any policy-based sandbox.
- `ScriptEngineManager().getEngineByName("groovy").eval(...)` — JSR-223 entry, same risk profile as `GroovyShell.evaluate`.
- `@Grab` / `Grape.grab(...)` inside scripts — pulls remote dependencies; if reachable, supply-chain RCE.

### Five questions to drive the triage verdict

1. **Where do scripts come from?** Bundled JAR resource / on-disk directory / database column / HTTP upload / git-pull / S3?
   - **Bundled in JAR (classpath, immutable at runtime):** strongest case for *reject*, but only if the load path is a fixed classpath URI (e.g. `getResource("rules/foo.groovy")`) with no override mechanism (no env-var / config-property fallback that switches to filesystem).
   - **On-disk directory:** confirm unless the directory perms are demonstrably 0700 owned by the JVM user AND no application code (admin endpoint, migration job, ops script) writes to it.
   - **Database column:** confirm. Even if the writer endpoint requires `ROLE_ADMIN`, that is admin-compromise = RCE — usually a finding the team should accept and document, not silently reject.
   - **HTTP upload / user-controllable path:** confirm unconditionally. Highest severity.

2. **Who can write to the script source?** Walk every code path that produces a write. Use `code-index` to find references to the source path / DB table / S3 bucket. Any unauthenticated or low-privilege writer turns this into pre-auth RCE.

3. **Is the source path itself user-controllable?** `engine.run("scripts/" + name + ".groovy", ...)` with attacker-controlled `name` is a path-traversal-to-RCE — confirm. Even `name` allowlisted to `[a-z]+` is suspicious if filenames in the directory are not exhaustively trusted.

4. **What does the `Binding` expose?** Each variable in `binding.setVariable(...)` is a capability granted to scripts:
   - `applicationContext` / Spring `BeanFactory` → script can `getBean("dataSource")` → arbitrary SQL, bypass repositories.
   - `groovy.sql.Sql` instance → direct DB access ignoring auth/audit.
   - `RestTemplate` / `WebClient` → SSRF amplifier from server identity.
   - `File` / `Path` rooted at app dir → arbitrary read/write within that root, often enough for code-overwrite.
   - Even a "harmless" service bean with reflection-accessible fields exposes its dependencies — note the transitive reach.
   - **In reasoning, list every binding variable and what it grants. A "tight" binding ≠ safe (script bypasses it via `Class.forName`), but a wide binding is itself a finding.**

5. **Is there a `CompilationCustomizer` chain?** Look for `CompilerConfiguration.addCompilationCustomizers(new SecureASTCustomizer()...)` or `ImportCustomizer`. Read the policy:
   - Receiver allowlist? Method allowlist? Star-import blocked? Reflection (`java.lang.reflect.*`) blocked?
   - Even with full restrictions: AST-level controls do not stop runtime tricks (dynamic method invocation through unblocked classes). **Note presence and content of the customizer — do not rely on it as sole defense.**

### Specific FP / TP patterns

- **TP — script body in `application.yml` / config server / DB, edited via admin UI:** confirm. Risk = admin compromise = RCE.
- **TP — `GroovyScriptEngine(["/opt/app/scripts"])` with that directory writable by deployment automation:** confirm. CI/CD compromise = RCE.
- **TP — `parseClass(httpResponse.body)` from any external service** (even "trusted" internal one, unless TLS + pinning + integrity verification): confirm — supply-chain compromise.
- **TP — `Binding` exposing `applicationContext` or any Spring bean tree:** even with tight script source control, note this as a defense-in-depth gap. Whether to confirm/reject depends on the source-control verdict; mention it in reasoning either way.
- **FP candidate — bundled rule scripts loaded from JAR via `getResourceAsStream("/rules/" + ALLOWLIST.get(key))`:** reject **only if** (a) `key` is from a closed enum/Map, (b) no fallback path goes to filesystem, (c) the JAR signing is verified at runtime or the deployment pipeline guarantees integrity.
- **FP candidate — script load path from `@Value("${rules.path}")` reading classpath: URI:** reject only if the property is fixed in code/config and not user-overridable via env-var or `-D` system property at startup; if the default can be overridden, the attack surface is "anyone with deploy access" — usually still confirm with caveat.

### What to capture in `triageReasoning` for these findings

When triaging a Groovy-scripting finding, the reasoning must explicitly answer:

```
Script source: <classpath | filesystem path | DB table.column | HTTP origin>.
Source writers: <list of code paths / endpoints / actors that can write>.
Loader: <GroovyClassLoader.parseClass | GroovyShell.evaluate | GroovyScriptEngine | ScriptEngine>.
Binding exposure: <list of variable names + what they grant>.
Customizer / sandbox: <none | SecureASTCustomizer policy summary | groovy-sandbox>.
Decisive fact: <e.g. "scripts loaded from /opt/app/scripts which is rw for the deploy user">.
```

This level of detail is required because runtime-script findings are blast-radius events, not local bugs — a future auditor must be able to reconstruct the full trust model from the reasoning alone.

## Output

Your reasoning must name:
- **The taint source** (e.g. `OrderController.create(@RequestBody OrderDto)` line N).
- **The sink symbol** (e.g. `OrderRepository.findRaw(String)` line M).
- **Each guard between source and sink** (validators, allowlists, escaping).
- **The decisive fact** (concatenated SQL on line M / parameterised query / specific allowlist).

Then call `update_triage_result` with the verdict.
