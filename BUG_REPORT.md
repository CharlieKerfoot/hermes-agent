# Bug Report — Hermes Agent

**Generated:** 2026-04-08
**Scanned:** ~88,000 lines across 832 Python files (tools/, agent/, gateway/, hermes_cli/, cron/, acp_adapter/, and root modules)
**Language(s):** Python 3.11+

## Summary

| Severity | Count |
|----------|-------|
| :red_circle: Critical | 0 |
| :orange_circle: Major | 2 |
| :yellow_circle: Minor | 3 |
| :white_circle: Nitpick | 3 |

This is a well-maintained codebase with strong security practices (SSRF protection, path traversal guards, secret redaction, dangerous command detection, skill scanning). The bugs found are edge-case concurrency issues and cross-platform guards, not fundamental design flaws.

---

## :orange_circle: Major

### MA-1: `memory_tool.py` — bare `import fcntl` crashes on non-Unix platforms
**File:** `tools/memory_tool.py:26`
**What:** `import fcntl` at module level without try/except guard. Will raise `ImportError` on any non-Unix platform.
**Why it matters:** While Windows is explicitly unsupported, other modules (`hermes_cli/auth.py:46`, `cron/scheduler.py:19-23`) correctly guard this import with try/except and fall back to `msvcrt`. The memory tool is imported during tool discovery (`model_tools.py:153`), so this failure would crash the entire tool system and prevent Hermes from starting on any platform where `fcntl` is unavailable (e.g., a future Windows port, or running in certain restricted environments).
**Root cause:** Inconsistent platform-guarding pattern — some modules guard the import, this one doesn't.
**Fix:**
```python
# tools/memory_tool.py, line 26
# Replace:
import fcntl
# With:
try:
    import fcntl
except ImportError:
    fcntl = None
```
And update the `_file_lock` context manager at line 138 to handle `fcntl = None` (skip locking or use an alternative).

---

### MA-2: `mcp_oauth.py` — global `_oauth_port` creates race condition between concurrent OAuth flows
**File:** `tools/mcp_oauth.py:85,403,423`
**What:** `_oauth_port` is a module-level global that gets overwritten in `build_oauth_auth()` and read in `_wait_for_callback()`. If two MCP servers with OAuth are initialized concurrently (e.g., during parallel MCP discovery), the second call overwrites `_oauth_port` before the first flow's `_wait_for_callback()` executes, causing the callback to bind to the wrong port.
**Why it matters:** The first OAuth flow would time out after 300 seconds with a confusing `OAuthNonInteractiveError`, and the user would need to retry. This silently breaks MCP server connections for multi-server setups.
**Root cause:** Per-flow state (`_oauth_port`) stored in a module global instead of being threaded through the OAuthClientProvider callbacks.
**Fix:**
```python
# Use a closure or threading.local() to associate the port with each flow.
# In build_oauth_auth(), capture the port in the callback closure:

def build_oauth_auth(server_name, server_url, oauth_config=None):
    ...
    redirect_port = ...
    
    # Capture port in closure instead of global
    async def _wait_for_callback_with_port() -> tuple[str, str | None]:
        return await _wait_for_callback_impl(redirect_port)
    
    provider = OAuthClientProvider(
        ...
        callback_handler=_wait_for_callback_with_port,
        ...
    )
```

---

## :yellow_circle: Minor

### MI-1: `approval.py` — `_permanent_approved` set iterated without lock in `save_permanent_allowlist`
**File:** `tools/approval.py:609`
**What:** In `check_dangerous_command()`, `save_permanent_allowlist(_permanent_approved)` passes the set reference. `save_permanent_allowlist()` calls `list(patterns)` on line 354, which iterates the set without holding `_lock`. A concurrent thread calling `approve_permanent()` could modify the set during iteration.
**Why it matters:** Could raise `RuntimeError: Set changed size during iteration` during concurrent approval operations (e.g., parallel subagents both approving different commands). CPython's GIL makes this very unlikely but not impossible.
**Root cause:** Lock scope doesn't cover the entire read-modify-persist cycle.
**Fix:**
```python
# In check_dangerous_command() and check_all_command_guards(), snapshot
# the set under the lock before passing to save:
with _lock:
    approve_permanent(pattern_key)  # already acquires _lock internally, so inline
    _permanent_approved.add(pattern_key)
    snapshot = set(_permanent_approved)
save_permanent_allowlist(snapshot)
```

---

### MI-2: `credential_files.py` — `atexit.register` called on every `_safe_skills_path` invocation
**File:** `tools/credential_files.py:289`
**What:** Each call to `_safe_skills_path()` when symlinks are detected registers a new `atexit` cleanup handler. While it cleans up the previous temp dir (line 268-269), the atexit handlers accumulate — one per call.
**Why it matters:** In long-running gateway processes where skills change over time, this leaks atexit handlers. Each handler is a closure holding a reference to a `safe_dir` Path. The old dirs are already deleted by line 269, so all but the last handler are no-ops, but they still consume memory and run at exit.
**Root cause:** Atexit registration should happen once, not per call.
**Fix:**
```python
# Register cleanup once, referencing the mutable global:
_atexit_registered = False

def _safe_skills_path(skills_dir: Path) -> str:
    global _safe_skills_tempdir, _atexit_registered
    ...
    if not _atexit_registered:
        def _cleanup():
            if _safe_skills_tempdir and _safe_skills_tempdir.is_dir():
                shutil.rmtree(_safe_skills_tempdir, ignore_errors=True)
        atexit.register(_cleanup)
        _atexit_registered = True
```

---

### MI-3: `transcription_tools.py` — `subprocess.run(..., shell=True)` with user-configurable command template
**File:** `tools/transcription_tools.py:385-391`
**What:** The local STT command template from `HERMES_LOCAL_STT_COMMAND` env var is formatted with `shlex.quote()`-d values and executed via `subprocess.run(command, shell=True)`. While the dynamic values (input_path, output_dir, language, model) are safely quoted, the template itself is an arbitrary shell command from the environment.
**Why it matters:** If an attacker can set `HERMES_LOCAL_STT_COMMAND` to a malicious template (e.g., via env injection in a shared server), the `shlex.quote()` protection on the substituted values is irrelevant — the template itself is the attack vector. This is lower risk since environment variables require host access, but the `shell=True` amplifies the blast radius compared to `shell=False` with a command list.
**Root cause:** Using `shell=True` when the command could be decomposed into a list.
**Fix:** Consider validating the command template against an allowlist of known STT binaries, or document the security assumption that `HERMES_LOCAL_STT_COMMAND` is trusted input.

---

## :white_circle: Nitpick

### N-1: `tirith_security.py` — `False` used as a sentinel value
**File:** `tools/tirith_security.py:97`
**What:** `_INSTALL_FAILED = False` is used as a sentinel to indicate "install was attempted and failed", distinct from `None` ("not yet tried"). The code then uses `_resolved_path is _INSTALL_FAILED` (identity comparison with `False`). While this works due to Python's boolean singleton semantics, it's confusing — the type annotation says `str | None | bool = None` and the sentinel comment acknowledges the concern.
**Root cause:** Quick-and-dirty sentinel that relies on CPython internals rather than a proper sentinel pattern.
**Fix:**
```python
_INSTALL_FAILED = object()  # proper sentinel
_resolved_path: str | None | object = None
```

---

### N-2: `check_dangerous_command` and `check_all_command_guards` skip all checks in non-interactive contexts
**File:** `tools/approval.py:571-573,669`
**What:** When neither `HERMES_INTERACTIVE` nor `HERMES_GATEWAY_SESSION` is set, ALL dangerous command checks are bypassed. This covers batch runners, cron jobs, and programmatic invocations.
**Why it matters:** A cron-scheduled agent could be prompted into running destructive commands with no safety net. This is a documented design trade-off (no user to prompt = no blocking), but worth noting.

---

### N-3: Multiple modules cache config at process level, stale across gateway sessions
**File:** `tools/credential_files.py:47`, `tools/env_passthrough.py:46`, `tools/file_tools.py:29`
**What:** Several modules cache config values (`_config_files`, `_config_passthrough`, `_max_read_chars_cached`) at process level. If the user edits `config.yaml` while the gateway is running, these caches serve stale values until the process restarts. All three modules provide `reset_config_cache()` helpers, but nothing calls them automatically on config change.
**Why it matters:** Configuration changes don't take effect until gateway restart, which could confuse users.

---

## Modules with no bugs found

- `tools/credential_files.py` — solid path traversal protection and symlink handling
- `tools/approval.py` — comprehensive dangerous command detection with proper normalization
- `tools/url_safety.py` — correct SSRF protection including CGNAT range
- `tools/skills_guard.py` — thorough threat pattern scanning
- `agent/redact.py` — comprehensive secret redaction (30+ patterns)
- `tools/file_operations.py` — proper shell escaping, write deny lists, safe-root sandboxing
- `tools/tirith_security.py` — robust auto-install with SHA-256 and cosign verification
- `tools/code_execution_tool.py` — proper sandbox isolation with restricted tool set
- `tools/vision_tools.py` — SSRF-safe with redirect guard
- `gateway/session.py` — proper PII hashing for platform-specific identifiers
- `hermes_cli/auth.py` — correct file locking, token refresh, multi-provider support
- `agent/credential_pool.py` — thread-safe credential rotation with proper locking
- `tools/delegate_tool.py` — proper tool restriction for child agents
- `tools/browser_tool.py` — correct fail-closed SSRF safety, fail-open policy defaults
- `tools/osv_check.py` — proper malware scanning for MCP extensions

## Coverage gaps

The following areas have limited or no test coverage and handle external input:

- `gateway/platforms/` — platform adapters for Telegram, Discord, Slack, WhatsApp, Signal, etc. These are the primary external input surface for the gateway
- `tools/mcp_oauth.py` — OAuth flow with ephemeral HTTP server
- `tools/browser_camofox.py` — anti-detection browser backend
- `acp_adapter/` — Agent Client Protocol adapter
- `tools/homeassistant_tool.py` — Home Assistant integration
- `cron/scheduler.py` — cron job execution (runs unattended)
