# Oranovix Guardian — Development Progress

## Fixes from the full audit (main @ f1d1b43)

Every item was reproduced first by a failing test, then fixed. Baseline before the fixes: 1777 passing, 5 skipped, pyright 0 errors.

### Phase 1: data location (branch `fix/data-location`)

Problem: the installer puts the exe in Program Files, and the exe wrote every data file next to itself. For a normal user that folder is read-only, so the alarm center, the scan history, the feed and event stores and the OSV update failed with `sqlite3.OperationalError: unable to open database file`, and the AI consent was never saved.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `AppPaths` is the only place that knows where data lives: `ORANOVIX_DATA_DIR` if set; the installed exe on Windows uses `%LOCALAPPDATA%\Oranovix Guardian` (then `%APPDATA%`, then the home folder); from source the project root as before. The folder is created on first use. Resources (assets, translations, `default_rules.json`, the sample log) come from the bundle (`sys._MEIPASS`). `DataFile` names every data file. | `core/app_paths.py` |
| 2 | All stores take their path from `AppPaths`: settings, `scan_history.db` (also the alarm memory), `integrity.db`, `feed.db`, `security_events.db`, `log_sentinel_state.db`, `osv.db`, `rules/custom_rules.json`, `reports/output`. The six copies of the frozen/source path logic are gone. The rule engine now loads `default_rules.json` from the bundle; before, the exe looked for it next to itself and found nothing. | the stores, `scanner_engine/rule_engine.py`, `reports/pdf_generator.py`, `gui/pages/reports_page.py` |
| 3 | `SettingsFile` owns `settings.json`: one lock per file for the whole process, read-modify-write under that lock, write to a temp file then `os.replace`. A file that does not parse (or is not an object) is renamed to `settings.json.corrupt-<timestamp>` instead of being overwritten with one section. ThemeManager, SoundManager, GeminiConfig, LiveDefenseSettings, ThreatFeedSettings and the Log Sentinel settings all use it. | `core/settings_file.py` |
| 4 | `StorageProblems`: a failed write (settings, scan history, custom rules) is reported once per file. The window shows it in the status bar and a warning dialog that names the file, the reason and the data folder. Problems before the window exists are kept and shown when it does. | `core/storage_problems.py`, `gui/app.py` |
| 5 | Migration: on start, data files that an older version wrote next to the exe are copied into the data folder, once (a marker file stops later copies). Existing files in the data folder are never overwritten; the old files are never deleted. | `core/app_paths.py`, `main.py` |
| 6 | Single instance per data folder: a named mutex on Windows, an exclusive lock file elsewhere. A second start shows a message, brings the running window to the front and exits. | `core/single_instance.py`, `main.py` |
| 7 | Installer: still `{autopf}`, no `settings.json` in `[Files]` (defaults come from the code), no `[UninstallDelete]` of runtime files in `{app}`. Version 1.1.0 everywhere (`core/version.py`, installer, status bar). | `build_tools/installer.iss`, `core/version.py`, `gui/status_bar.py` |
| 8 | Tests: the exe is simulated with `sys.frozen` in a folder that is really read-only (chmod 555, plus an ACL deny entry on Windows, where chmod does not protect a folder); every store, the OSV update target, the consent, custom rules and the PDF output work and write into the data folder, and the install folder stays untouched. Migration, corrupt file, parallel writers, failed write reported once, second instance (in-process and as a second process), installer and version. The test session now sets `ORANOVIX_DATA_DIR` to a temp folder, so tests never write into the project root. | `tests/test_data_location.py`, `tests/conftest.py` |

Tests: 1809 passing, 5 skipped (32 new). Type check: `uvx pyright`, 0 errors.

Known limits:

- The data folder is per Windows user. Two users on one machine each have their own settings, baselines and history.
- Uninstalling keeps the data folder. It has to be deleted by hand to remove everything.
- Migration copies only the known data files; old PDF reports in `{app}\reports\output` stay where they are.
- The single-instance check is per data folder: a copy started with another `ORANOVIX_DATA_DIR` is allowed, because it does not share any database.
- On Windows the second start finds the running window by its title; if it cannot be found, only the message is shown.

### Phase 2: false positives (branch `fix/false-positives`)

Problem: `DangerousFunctionRule` matched any method called `eval`, `exec` or `compile`, so `re.compile`, `model.eval()` and `df.eval` were CRITICAL (22 CRITICAL in a copy of requests and urllib3), and Live Defense rang a CRITICAL alarm with sound when a views.py gained `re.compile`. Placeholder secrets (`token = "test"`) were CRITICAL, B105 and B607 were promoted for form field names and literal command lists, md5 with `usedforsecurity=False` was flagged.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Dangerous call rule: only the builtins `eval`, `exec`, `compile`, called by bare name or as `builtins.x` / `__builtins__.x`, and only if the module does not bind that name itself (import, assignment, def, parameter; `from builtins import eval` still counts). CRITICAL when the code argument is not a constant string, MEDIUM when it is. A `ModuleContext` gives rules facts about the whole module. | `scanner_engine/ast_analyzer.py` |
| 2 | `SecretHeuristics`: placeholder values (test, changeme, xxx, example, dummy, empty, template variables like `${X}` or `{{ x }}`, values under 8 characters, URLs without a password, paths) and names ending in `_url`, `_field`, `_header`, `_name`, `_path`, `_label` (also `_uri`, `_file`) are not secrets. Used by SEC001, AST-SEC1, the secrets detector's password rule SEC-PWD01 and the Bandit promotion of B105/B106/B107. | `scanner_engine/secret_heuristics.py`, `scanner_engine/python_scanner.py`, `scanner_engine/secrets_detector.py` |
| 3 | AST-CRY1 skips `hashlib.md5(..., usedforsecurity=False)`. | `scanner_engine/ast_analyzer.py` |
| 4 | `BanditSeverityPolicy` looks at the flagged line before promoting: B105/B106/B107 only when confidence is not LOW and the name and value look like a secret; B603/B607 only when confidence is not LOW and the command is not a literal (string or list of strings); B102/B307 CRITICAL only when the code is not a constant string, MEDIUM otherwise. Unpromoted findings keep Bandit's own severity. | `scanner_engine/python_scanner.py` |
| 5 | Live Defense: `ChangeClassifier.cap_findings` holds code-scan findings at MEDIUM for a modified file and at HIGH for a new one, except secrets and code or command execution (which the scanner rates CRITICAL only for non-constant input). Web shells still come in as signature hits and stay CRITICAL. The capped findings are also what the alarm center receives, so a capped finding cannot ring on its own. | `live_defense/classifier.py`, `live_defense/file_integrity.py` |

Tests: 1886 passing, 5 skipped (77 new). Type check: `uvx pyright`, 0 errors. The findings on `tests/corpus` are identical before and after (same files, lines, categories and severities). A copy of the installed requests and urllib3 now has 0 CRITICAL findings (was 22).

Known limits:

- "Not rebound" is checked for the whole module: if a module defines its own `eval` anywhere, a call to the builtin `eval` elsewhere in that module is not reported.
- `exec` of a constant string is MEDIUM. Code that builds the string first and passes a variable is CRITICAL even when the variable only ever holds a constant.
- The placeholder list is a heuristic. A real password shorter than 8 characters is no longer promoted; Bandit still lists it with its own (LOW) severity.
- Command execution keeps its scanner severity in a changed file, not only code execution: an existing test requires a CRITICAL command-execution finding in a modified file to stay CRITICAL.

### Phase 3: scanner robustness (branch `fix/scanner-robustness`)

Problem: a Python file with a 100,000-term expression raised RecursionError in the AST analyzer; the Python engine only caught OSError, so it aborted and every file sorted after it lost its Django, settings and AST findings (DJ005, DS001, SEC001 disappeared after adding `aaa_data.py`). Symlinks out of the project were read, imported regexes were never checked, and `migrations` was never scanned.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `BaseScanner.isolated` runs one file (or one analyzer on one file) and turns any exception, including RecursionError and MemoryError, into the warning `<file>: not analysed (<what>: <reason>)`; the scan goes on. The Python engine isolates its regex checks, AST rules, Django rules and Django settings rules separately per file. `scan_each` does the same for the JS, PHP, Java, C#, template and secrets scanners; the orchestrator does it for the rule engine. | `scanner_engine/base.py`, `scanner_engine/python_scanner.py`, the scanners, `scanner_engine/orchestrator.py` |
| 2 | Files above 5 MB (`BaseScanner.MAX_FILE_BYTES`) are not read; they appear once in the warnings ("larger than 5 MB"). The orchestrator drops duplicate warnings. Bandit gets the same capped list. | `scanner_engine/base.py`, `scanner_engine/orchestrator.py` |
| 3 | `collect_files` (and the manifest walker) follow a symlink or junction only when its real path is inside the scan root. | `scanner_engine/base.py`, `scanner_engine/deps/manifests.py` |
| 4 | Custom rules: each pattern is compiled once per process (`lru_cache`). Invalid regexes, and repeated groups that contain a repeat or alternatives (`(a+)+`, `(\w*)*`, `(a|aa)*`), are refused with a message: on import (shown in a dialog), on "add rule" (shown in the dialog), and on every load, so a file saved by an older version cannot hang a scan either (listed in the scan warnings). Rules run line by line on the first 1000 characters of each line. | `scanner_engine/rule_engine.py`, `gui/pages/settings_page.py` |
| 5 | Folders: `venv`, `.venv`, `node_modules`, `.git`, `site-packages`, `__pycache__`, `dist` are still skipped. `migrations` is scanned. `env` and `build` are skipped only when they hold a virtual environment (`pyvenv.cfg`) or build output (setuptools `bdist.*`/`lib.*`/`temp.*`, PyInstaller `.toc` files, CMake). A folder with `pyvenv.cfg` is skipped under any name. | `scanner_engine/base.py` |

Tests: 1925 passing, 6 skipped (39 new; the new file-symlink test skips because this account may not create symlinks, the junction tests run). Type check: `uvx pyright`, 0 errors. Findings on `tests/corpus` unchanged.

Known limits:

- The pattern check is a heuristic. It refuses some harmless patterns (`(?:foo|bar)+`; a character class or a non-repeated group works instead), and polynomial patterns such as `\w*\w*\w*x` pass it; the 1000-character line cap keeps those bounded but not instant.
- Rules see only the first 1000 characters of a line: a match further right in minified code is missed.
- A file the antivirus locks is read as empty by the line scanners (unchanged behaviour); only the Python engine reports it as unreadable.
- Generated `build` folders are recognised by setuptools, PyInstaller and CMake markers only; other build output is scanned.

## Log Sentinel (branch `feature/log-sentinel`)

Goal: read the web server's access logs on this computer, report attacks, and link them with the file integrity monitor. Detection only: nothing is blocked and nothing from the logs is sent anywhere.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Package `log_sentinel`. `AccessLogEntry`; `LogParser` (ABC) with `NginxCombinedParser` (nginx and Apache combined and common, optional `X-Forwarded-For` field) and `JsonLinesParser` (configurable field map, dotted keys, nginx `escape=json` and Caddy work as they are); `LogFormatDetector` samples the first 20 lines. Lines are capped at 8192 characters before any regex, the patterns have no nested quantifiers, malformed lines are counted and skipped. A 1 MB hostile line takes about 1 ms. `X-Forwarded-For` is used only when the direct peer is in the trusted proxy list (empty by default). | `log_sentinel/entry.py`, `log_sentinel/parsers.py` |
| 2 | `RequestNormalizer`: up to three rounds of URL decoding, overlong UTF-8 and `%u` forms, plus-to-space in the query, NFKC, null bytes removed, case folded, SQL comments (`/**/`, `/*!50000`, `--`, `#`) removed. Eleven `AttackRule` classes (SQL injection, XSS, path traversal and LFI, remote file inclusion, command injection, SSRF, template injection, Log4j, sensitive files, foreign admin panels, scanner user agents), each with id, title, category, base severity and an explanation in AR/DE/EN. `ResponseJudge` raises a payload one level when it got a 2xx that is not the usual error page (learned from 4xx sizes; a size that answers many attacks is a catch-all page and stops raising). 400/403/404/405/444 keep the base severity. Measured on a true positive corpus (102 payloads, 8+ per family, each also double encoded and in mixed case) and a false positive corpus (Django admin, searches with apostrophes, blog slugs with "union select" or "etc-passwd", `script-v2.js`, base64 image data): no false positives. | `log_sentinel/normalize.py`, `log_sentinel/rules.py`, `tests/fixtures/log_sentinel/` |
| 3 | `BruteForceRule` (10 failures from one address on one login path in 5 minutes: 401/403, or a POST 200 the size of the error page, HIGH; then a redirect or a 200 of another size: CRITICAL "possible successful brute force"), `ScanRule` (more than 30 distinct 404 paths in 2 minutes MEDIUM, more than 100 HIGH), `FloodRule` (more than 300 requests a minute, MEDIUM, configurable). Allowlist of addresses and ranges skipped entirely. State per address is dropped after its window, at most 50,000 addresses are tracked. | `log_sentinel/behaviour.py` |
| 4 | `LogSentinelMonitor` (subclass of `Monitor`): tails one or more logs, offset and file identity (inode / Windows file index) in `log_sentinel_state.db`, follows rotation (reads the rest of `<name>.1` first) and truncation, starts at the end of a new log or reads its last N MB once, at most 5 MB per cycle, every 10 seconds. Events are folded per rule, address, 10-minute window and severity, and alarm once through `AlarmCenter` with the new category `ATTACK`: CRITICAL with sound, flash and red banner, HIGH as a toast. `PlantedPathProvider` links the file integrity monitor: when a script or a suspicious file that it reported in a public folder is served (2xx/3xx), one CRITICAL event names both. 100,000 lines in about 3.5 s. | `log_sentinel/monitor.py`, `log_sentinel/tail.py`, `log_sentinel/events.py` |
| 5 | `SecurityEventStore` in `security_events.db`: truncated address (IPv4 /24, IPv6 /48) unless full addresses are switched on, a keyed hash for counting (key in the credential store, or beside the events), the normalised request cut to 300 characters with credential values hidden, status, reason, open/acknowledged. Top attackers by hash, counts per rule and per day, acknowledge one or all, retention 30 days (configurable) applied on every start. CSV export (cells that look like formulas are written as text) and the PDF section "Attacks seen in web logs". | `log_sentinel/store.py`, `log_sentinel/privacy.py`, `log_sentinel/export.py`, `reports/pdf_generator.py` |
| 6 | Page "Log Sentinel": log files with format, start/stop, interval, retention, trusted proxies, allowlist, "Keep full IP addresses" with a DSGVO note, events with filters and acknowledge buttons, CSV export, top addresses, red banner for open CRITICAL events. Sidebar badge for open CRITICAL and HIGH, "Watching logs" in the status bar, resume question on start. "Analyse a sample log" reads `assets/sample_access.log`. AR/DE/EN. | `log_sentinel/controller.py`, `gui/pages/log_sentinel_page.py`, `gui/app.py`, `gui/sidebar.py`, `gui/status_bar.py` |
| 7 | Tests that attack the feature: SQL injection behind encodings, case, comments and full-width characters; a 1 MB line; rotation while reading; 50,000 addresses; a benign day of 5,000+ lines; brute force then 302; a web shell planted and served, with the real file integrity monitor. They found two misses that are fixed (a tautology in brackets, the unread rest of a rotated log). | `tests/test_sentinel_adversarial.py` |

Tests: 1777 passing, 5 skipped (501 of them for Log Sentinel). Type check: `uvx pyright`, 0 errors. Tests never touch the network and never sleep.

### Known limits

- Detection only. Nothing is blocked; there is no firewall rule and no live connection to the web server.
- One log path is one server: behaviour rules (brute force, scans, floods) count per watched file. The same attacker on two servers is two counts.
- JSON field mapping is configurable in `settings.json` (`log_sentinel.json_fields`) but not detected automatically. Without a matching mapping JSON lines count as malformed.
- Addresses are truncated to /24 (IPv4) and /48 (IPv6). Different attackers in one /24 look the same in the table; the hash still tells them apart for counting.
- `X-Forwarded-For` is ignored until the user enters the trusted proxies. Behind a proxy or a CDN without that setting, every request seems to come from the proxy, so brute force and flood rules see one address.
- At most three layers of URL encoding are undone. A fourth layer stays encoded (and would not work against a server that decodes once or twice either).
- A planted file is linked only when it is a script type or the integrity monitor rated it HIGH or CRITICAL, so a changed stylesheet after a deploy is not reported as a web shell. A planted image that is served is not linked.
- Rotation: the rest of the old file is read only when it was renamed to `<name>.1`. With date suffixes or compression right away, lines written between the last read and the rotation are lost.
- The response judgement is a guess: a 2xx that is not the usual error page may also be a normal page that ignores the payload. Sites that answer every probe with the same 200 page are learned after five such answers.
- Brute force on a login that answers failures with a redirect (302 back to the form) is counted only through 401/403; the 302 is taken as a possible success.
- The hash key is kept in the Windows credential store. Without one it is stored next to the events, so the hash is a pseudonym, not protection against someone who has the database file.
- Sample log analysis stores its events like real ones (source `sample_access.log`); acknowledge them, or they are removed after the retention period.

### Notes for the next build

- New databases next to `settings.json`: `security_events.db` and `log_sentinel_state.db` (gitignored).
- `assets/sample_access.log` must ship with the exe; it is in `assets/`, which the spec already collects. `.gitignore` has an exception for it, because `*.log` is ignored.
- No new dependencies.

---

## Threat Feed and My Projects (branch `feature/threat-feed`)

Goal: daily security news and exploited vulnerabilities, matched on this machine against the user's own projects, plus uptime checks of their sites.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Package `threat_intel`: `FeedItem`, `Relevance`, `FeedSource` (ABC), `HttpFetcher` (https only, 10 s timeout, 5 MB cap, User-Agent `OranovixGuardian`, ETag / If-Modified-Since, 304 = unchanged). All feed text is cleaned: tags and entities stripped, title 200 and summary 400 characters, only http/https links. | `threat_intel/models.py`, `threat_intel/fetcher.py`, `threat_intel/sanitize.py` |
| 2 | `CisaKevSource` (every entry, cap 5000; see the gap fixes below) and `RssSource` (newest 200 items) (RSS 2.0, RSS 1.0, Atom, parsed with defusedxml, no DTD allowed). Source list in `settings.json`. Each source keeps its own health; one failing source does not stop the others. | `threat_intel/sources.py`, `threat_intel/settings.py` |
| 3 | `ThreatStore` in `feed.db`: dedupe by id, read flag, first seen, unread counts per relevance, items no feed has listed for 90 days are removed. The page always reads the cache and shows the last successful update. | `threat_intel/store.py` |
| 4 | `ProjectRegistry` (name, folder, optional site address), `InventoryBuilder` on the existing manifest parsers, `ScanSummaryLookup` for the latest entry of the scan history. | `threat_intel/projects.py` |
| 5 | `RelevanceMatcher`: AFFECTS_YOU when a CVE id leads to a local OSV advisory whose range contains an installed version; POSSIBLE when only a vendor or product name matches; GENERAL otherwise. Uses `OSVDatabase` and `VersionMatcher`, nothing is duplicated. | `threat_intel/relevance.py` |
| 6 | One CRITICAL alarm per item and project when the item affects a project and is exploited (KEV) or its advisory is CRITICAL. Remembered in `feed.db`, so it is raised once. | `threat_intel/alarms.py`, `threat_intel/service.py` |
| 7 | `UptimeMonitor` (subclass of `Monitor`): GET every 5 minutes, 10 s timeout, status and response time, last 100 checks per project. Three failures in a row raise one HIGH alarm; one recovery event when the site is back. | `threat_intel/uptime.py` |
| 8 | Pages "Threat Feed" (For you, All, Sources) and "My Projects", sidebar badge, Settings section, first-run dialog that names the hosts. Off by default. Refresh runs in a background thread. Texts in AR/DE/EN. | `threat_intel/hub.py`, `gui/pages/threat_feed_page.py`, `gui/pages/projects_page.py`, `gui/threat_feed_dialogs.py`, `gui/app.py`, `gui/sidebar.py`, `gui/pages/settings_page.py` |
| 9 | `DigestBuilder`: pure function from items, projects and "since" to plain text and HTML. No sending in this branch. | `threat_intel/digest.py` |

Tests: 1164 passing, 5 skipped. Type check: `uvx pyright`, 0 errors. Tests never touch the network (fake fetcher).

Feed addresses, checked on 2026-11-16 against the publishers' own pages:

- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- BleepingComputer: `https://www.bleepingcomputer.com/feed/`
- The Hacker News: `https://feeds.feedburner.com/TheHackersNews`
- BSI CERT-Bund: `https://wid.cert-bund.de/content/public/securityAdvisory/rss`

### Gap fixes (branch `fix/threat-feed-gaps`)

| Fix | Change | Main files |
|-----|--------|-----------|
| 1 | The whole CISA catalog is kept and matched. Before, only the newest 200 entries were, so an old exploited vulnerability in a project was never flagged. `CisaKevSource.MAX_ITEMS` is 5000; news sources keep 200. A catalog entry older than 30 days is stored as a background item (`items.background`): it is matched like every other item, but it is not counted as new, as unread or in the sidebar badge until it affects a project. More than three alarms in one pass become one CRITICAL alarm (`TF002`) with the count and the first three by name. `feed.db` files of the first version get the new column on start. | `threat_intel/sources.py`, `threat_intel/store.py`, `threat_intel/service.py`, `threat_intel/alarms.py` |
| 1 (page) | "All" shows 200 items per page, newest first, with "Show more" for the next page. "For you" lists every item that affects a project first, whatever its age, then the guesses. Rows are built in batches from plain Tk widgets inside one card frame; a page of 200 rows draws in about 3 s (about 15 s before). | `gui/pages/threat_feed_page.py`, `threat_intel/hub.py` |
| 2 | `CheckState`: the "For you" tab, the digest line (page and status bar) and the feed column of My Projects say "Not checked: ..." with the reason while the feed is off, was never downloaded, reached no source, has no projects, or the OSV database is missing. "Nothing affects your projects" is shown only after a real check. | `threat_intel/hub.py`, `threat_intel/digest.py`, `gui/pages/threat_feed_page.py`, `gui/pages/projects_page.py` |
| 3 | Feed downloads refuse every address that is not globally routable. This adds 100.64.0.0/10 (carrier NAT, Tailscale). | `threat_intel/fetcher.py` |
| 4 | First-run dialog: "Switch on" has a visible border, and the window is as high as its content. | `gui/threat_feed_dialogs.py` |

Tests after the gap fixes: 1219 passing, 5 skipped. Type check: 0 errors.

### TLS trust and polish (branch `fix/feed-tls`)

| Fix | Change | Main files |
|-----|--------|-----------|
| 1 | Certificates are verified against the trust store of the operating system (`truststore`). Without that package the default context plus certifi's bundle is used. Verification is on in every case; there is no switch and no fallback that turns it off. Requests and redirects share one context. A certificate failure is stored as `CertificateError` and the Sources tab shows "The certificate of this site is not trusted by your system" with the technical text below. | `threat_intel/fetcher.py`, `gui/pages/threat_feed_page.py` |
| 2 | `CheckState.PARTIAL`: when the newest download of the CISA catalog failed, the For you tab and the digest line say "Partly checked: CISA KEV could not be read". A failed news feed does not change the result. Read from the stored source health, so it holds after a restart. | `threat_intel/hub.py` |
| 3 | A confirmed match without a fixed version shows "no fixed version known" (page and digest). | `gui/pages/threat_feed_page.py`, `threat_intel/digest.py` |
| 4 | Opening the page never marked anything as read, but opening the link of an item did. An item that affects a project now stays unread until Mark read or Mark all read is pressed. | `gui/pages/threat_feed_page.py` |

Why fix 1 was needed: `wid.cert-bund.de` sends four certificates, ending with the self-signed root "D-TRUST Root Class 3 CA 2 2009". Windows fetches roots on demand, and on the test machine that root was not in the store yet. Python reads only what is already in the store, so it reported "self-signed certificate in certificate chain". Windows itself accepts the chain, and so does `truststore`, which asks Windows.

Checked with the real network on 2026-11-17, verification on: CISA KEV, BleepingComputer, The Hacker News and BSI CERT-Bund all download, with `truststore` and also with the certifi fallback.

Tests after these fixes: 1251 passing, 5 skipped. Type check: 0 errors.

### Read is not fixed (branch `fix/open-exposure`)

A test with real data showed a false all clear: after the affecting items were marked read, My Projects said "Nothing" and the status bar said "0 affect your projects", while the project still pinned the vulnerable version. The project column and the headline counted unread items.

| Part | Change | Main files |
|------|--------|-----------|
| Model | `ExposureReport`: per project the confirmed items that hit it, worst first (exploited, then severity, then newest). It is built from the stored matches and never looks at the read flag. | `threat_intel/exposure.py` |
| Read flag | Only drives notifications: the sidebar badge, the "new" counter and the alarms. | `threat_intel/store.py` |
| My Projects | The Threat Feed column counts open items, read or not, in red. "Nothing" needs a successful full check with no match. Panel "Exposed projects" above the table: one line per exposed project with its worst item and the first fixed version that is known. | `gui/pages/projects_page.py`, `threat_intel/hub.py` |
| Headline | Two independent parts on the page and in the status bar: "Since your last visit: X new" and "Y of your projects are exposed". The second part is also shown when the feed is off or could not be read. | `threat_intel/digest.py` |
| For you tab | Items that affect a project are always listed, read or not, with their red project line. The switch "Show read items" (on by default) hides read guesses only. | `gui/pages/threat_feed_page.py` |
| Accept risk | Button on an affecting item. It asks for a short reason and stores it per item and project (`accepted_risks` in `feed.db`). The item stays listed in grey with the reason, counts as "accepted" in the project column, is not exposed any more and does not alarm. "Withdraw acceptance" takes it back. | `threat_intel/store.py`, `threat_intel/hub.py`, `gui/threat_feed_dialogs.py` |

An item stops counting in three ways only: the dependency is upgraded (seen by the next Refresh, or by a scan, which now matches the feed again without the network), the project is removed, or the risk is accepted.

Tests after this change: 1276 passing, 5 skipped. Type check: 0 errors.

### Known limits

- Name matching for KEV entries (vendor / product against package names) is approximate. It is shown as "possible match, verify" and never alarms.
- Only PyPI and npm packages can be confirmed, because that is what the local OSV database holds. Without that database nothing is confirmed.
- Feeds can change their addresses. A broken source shows its error in the Sources tab; the address is edited in Settings.
- Nothing is pushed while the app is closed. Feed and uptime checks run only while it is open.
- A feed with a DOCTYPE is rejected as a whole.
- The same CVE reported by two sources is two items, so it can alarm twice.
- Uptime checks run for every project with a site address, also while the feed is switched off.
- A catalog entry counts as background by its date alone (older than 30 days when it first arrives), not only on the very first refresh. After a long break the entries added in between arrive silently too; they are still matched and still alarm when they affect a project.
- More than three alarms at once are announced as one alarm that names three of them. The rest is listed in the "For you" tab only.
- "Partly checked" looks at sources of kind `kev` only. When the user disables or removes the CISA source, nothing says that exploited vulnerabilities are no longer checked.
- The feed column of My Projects has no text of its own for "partly checked"; it shows "Not checked".
- Exposure is as fresh as the last check. After a manifest was edited, the project column changes with the next Refresh, the next scan, or when a project is added or removed, not at once.
- With the feed switched off, Refresh does nothing, so an upgrade is only seen by a scan.
- Possible matches (name only) never count as exposure. They are guesses.
- "Accept risk" on an item applies to every project the item hits at that moment. There is no button for a single project, and no date on which an acceptance runs out.
- Opening the link of a news item or of a possible match still marks it as read. Only items that affect a project wait for the Mark read button.
- Uptime checks use the same trust store. A site with a certificate from a private CA is reported as failing unless that CA is installed in the system store.
- A page of the list holds at most 200 rows, because Tk cannot scroll a frame higher than 32767 pixels. With more than 200 items that affect projects, the rest is on the next page.
- The rows of the feed list are plain Tk widgets, so they do not follow a change of the display scaling while the app is open.
- Feed downloads refuse hosts that resolve to any address that is not globally routable (loopback, private, carrier NAT, link-local, reserved, multicast, unspecified), also after a redirect. The address is resolved once for the check and again by the connection, so a DNS answer that changes in between is not caught. Uptime checks are not limited this way, because the user's own site can be a local dev server.
- Links with user info before the host (`https://user:pw@host/`) are refused everywhere `SafeUrl` is used: feed items, the link opener, the digest and project site addresses. A site that needs basic auth in its URL cannot be monitored.

### Notes for the next build

- New dependency: `defusedxml`. Not merged; do not rebuild the exe from this branch yet.
- New dependencies from `fix/feed-tls`: `truststore` and `certifi`. PyInstaller may need `--hidden-import truststore`, because it is imported inside a function, and certifi needs `--collect-data certifi` for its `cacert.pem`. Without them the exe still verifies, with the default context only, and the BSI feed fails again on machines that lack the D-TRUST root.
- `feed.db` is written next to `settings.json` and is gitignored.

---

## Live Defense: file integrity (branch `feature/file-integrity`)

Goal: detect planted or modified files in a monitored project folder. This is the first Live Defense module.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `Monitor` (ABC): `start()`, `stop()`, `is_running`, abstract `check()`. One background thread per monitor with a stop `Event`; a failing cycle is reported and the thread keeps running. Results go out through an `on_report` callback; the monitor never touches Tk. Events of severity HIGH and CRITICAL go to the shared `AlarmCenter` with `full_scan=False`. | `live_defense/base.py` |
| 2 | `Baseline`: one SQLite table per monitored root in `integrity.db` (relative path, sha256, size, mtime). Files are hashed in chunks. Symlinks and junctions are recorded but never followed. All file types are covered. `EXCLUDED_DIRS`, `*.pyc`, `*.log`, `db.sqlite3` and user patterns are ignored. An HMAC-SHA256 over the sorted rows is stored with the table; its key is kept in the credential store (`SecretStore`, entry `file_integrity_hmac_key`). The HMAC is checked before every check. A mismatch, a missing record or a missing key gives a CRITICAL event "Baseline was modified outside the app". | `live_defense/baseline.py` |
| 3 | `FileIntegrityMonitor`: every N seconds (default 30) a quick pass compares size and mtime and hashes only changed files. Every 10th cycle, and the first one after start, re-hashes everything to catch timestomping. Events are NEW, MODIFIED and DELETED. Severity rules: a new executable in upload/media/static/public/tmp folders is CRITICAL; so are a double extension (`x.php.jpg`) and a web shell signature. A change to settings.py, `.env*`, wsgi/asgi/urls.py, `.htaccess`, nginx/apache conf or a Dockerfile is HIGH. Other source changes and deletions are MEDIUM, and new non-code files are LOW. There are six web shell rules, one class each. NEW and MODIFIED scannable files also go through `ScanOrchestrator`, and its findings are attached to the event and reach the alarm. The finding id contains the new sha256, so each new state alarms once. | `live_defense/file_integrity.py`, `live_defense/webshell.py` |
| 4 | Accepting: `accept(ids)` and `accept_all()` write the current state of those files into the baseline and re-sign it. Unaccepted events stay open. A tamper event cannot be accepted; only a new baseline clears it. Saving new ignore patterns drops matching rows, re-signs, and closes matching events. | `live_defense/file_integrity.py`, `live_defense/baseline.py` |
| 5 | Sidebar page "Live Defense" with folder, Create baseline, Start/Stop, interval, ignore patterns and the open events table. The table shows time, severity, change, type, path and reason, with Accept, Scan file, Accept all and a severity filter. `LiveDefenseController` owns the monitor, so it keeps running across theme and language rebuilds. It sends state to listeners through `widget.after` and stores root, interval and running in `settings.json`. A "Monitoring" badge appears in the status bar while a monitor runs. If monitoring was on when the app closed, the next start asks before resuming. Config files show the language "Config". Texts are in AR/DE/EN. | `live_defense/controller.py`, `gui/pages/live_defense_page.py`, `gui/confirm_dialog.py`, `gui/app.py`, `gui/sidebar.py`, `gui/status_bar.py`, `translations/` |
| 6 | Tests (no GUI, no sleeps, `check()` called directly) cover all the cases in the spec. Shell-shaped and key-shaped test values are built at runtime. | `tests/test_monitor_base.py`, `tests/test_baseline.py`, `tests/test_file_integrity.py`, `tests/test_accept_changes.py`, `tests/test_live_defense_controller.py` |
| 7 | `core/oranovix_security_report.pdf` is no longer tracked (the file stays on disk). `reports/output/` and `*security_report*.pdf` are ignored. | `.gitignore` |

Tests: 539 passing, 1 skipped. Type check: `uvx pyright`, 0 errors.

### Review fixes (second round)

A review found gaps in what the monitor could see and how it rated what it saw.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | The scanner's `EXCLUDED_DIRS` no longer applies. The monitor skips only `__pycache__`, `node_modules`, `venv`, `.venv`, `site-packages` and `.git/objects`, and not even those when any parent folder (or the monitored folder itself) is public. `build`, `dist`, `migrations`, `env` and the rest of `.git` (hooks!) are always watched. | `live_defense/baseline.py`, `live_defense/paths.py` |
| 2 | Names are normalised before classifying: trailing dots and spaces are dropped (Windows serves `shell.php.` as `shell.php`), and such files are opened through the extended-length path so their content is still read. Executable list: the PHP variants (`.php3`-`.php8`, `.pht`, `.phps`, `.inc`), `.asp`, `.ashx`, `.asmx`, `.cshtml`, `.jspx`, `.jspf`, `.cfm`, `.cgi`, `.pl`, `.bat`, `.ps1`, plus the earlier ones. The hidden-extension check uses all of them. | `live_defense/classifier.py`, `live_defense/baseline.py` |
| 3 | Public folders also include `files`, `images`, `img`, `assets`, `attachments`, `storage`, `cache`, `downloads`, `public_html`, `www` and `wp-content`. The monitored folder's own name counts, so monitoring `uploads` directly is public. Inside a public folder, `.htaccess`, `.user.ini` and `web.config` are CRITICAL (new, changed or deleted). | `live_defense/paths.py`, `live_defense/classifier.py` |
| 4 | Links: a new or changed symlink or junction is MEDIUM. It is HIGH inside a public folder, and CRITICAL when it is in a public folder and resolves outside the monitored folder. The reason names the target. Link content is not scanned. | `live_defense/classifier.py`, `live_defense/baseline.py` |
| 5 | Seven new signatures, one class each: eval/assert/create_function/include/require on superglobals; backtick execution of input; a superglobal called as a function; eval of gzinflate/gzuncompress/str_rot13 chains; `preg_replace` with `/e`; a function name glued from string pieces and called on input; Python eval/exec/compile/`__import__` on request data. Each has at least two hits and two near misses in the tests. Every rule has key words it needs, so a rule skips text that cannot match. A 1.6 MB plain Python file now takes 0.01 s instead of about 0.4 s. | `live_defense/webshell.py` |
| 6 | Files are scanned in 1 MB chunks with a 256-byte overlap, up to 50 MB (it used to be the first 5 MB). A bigger file gets "File too large to scan fully" and is at least MEDIUM. | `live_defense/webshell.py` |
| 7 | A HIGH or CRITICAL code-scan finding (with confidence other than LOW) now sets the event severity, and the reasons name it with its line. The event list now shows the same severity as the alarm. | `live_defense/classifier.py` |
| 8 | Creating a baseline first checks every file. A file is left out of the baseline if it has a web shell signature, a hidden executable extension, an executable in an upload-type folder, or is a link in a public folder. The first check then reports it as NEW with its real severity and sounds the alarm. `create_baseline` returns the count and the refused files. The page shows "N files look suspicious and were left out of the baseline" with the list (AR/DE/EN). Code in web roots (`static`, `public`, `assets`, `public_html`, `www`, `wp-content`, `cache`, `storage`) is not refused for its extension alone, because a site's own JS and PHP live there. | `live_defense/baseline.py`, `live_defense/classifier.py`, `live_defense/controller.py`, `gui/pages/live_defense_page.py` |

Tests: 971 passing, 5 skipped (the symlink tests need a right this account lacks; the same cases run with directory junctions). Type check: `uvx pyright`, 0 errors.

Attack matrix, run by hand with the real monitor, signatures and scan engine. Every row raised an alarm except the plain image:

| Attack | Event | Severity |
|--------|-------|----------|
| Shell in `public/build/` | NEW, web shell signature | CRITICAL |
| Shell in `static/dist/` | NEW, web shell signature | CRITICAL |
| Shell in `static/node_modules/` | NEW, web shell signature | CRITICAL |
| Shell in `.git/hooks/` | NEW, web shell signature | CRITICAL |
| `uploads/x.php5`, `.pht`, `.asp`, `.ashx` (harmless body) | NEW, executable in uploads/ | CRITICAL |
| `uploads/shell.php.` (trailing dot) | NEW, content read, web shell signature | CRITICAL |
| `.htaccess` in uploads | NEW, server configuration file in uploads/ | CRITICAL |
| Root named `uploads`, new `shell.php` | NEW | CRITICAL |
| Root named `uploads`, new `photo.jpg` | NEW | LOW, no alarm |
| Link to a system folder in uploads (junction; symlinks not permitted here) | NEW, points outside the monitored folder | CRITICAL |
| Payload after 6 MB of padding | NEW, signature found on line 62916 | CRITICAL |
| Baseline created on a folder with a shell | shell left out of the baseline, NEW on first check | CRITICAL |

### Known limits

- This is still timer based, not file system events. A file that is planted and removed again between two checks is not seen.
- One monitored folder at a time.
- Open events live in memory. After a restart, unaccepted changes are found again on the first check, which is a full pass.
- A timestomped change (same size and mtime) is only found by the full re-hash, so it can take up to 10 intervals.
- The HMAC protects the baseline against edits outside the app. An attacker who can read the user's credential store can still re-sign it.
- Signatures longer than the 256-byte overlap (a base64 literal over 2000 characters, or a glued name called more than 256 bytes later) can be missed when they cross a 1 MB chunk border. Only the first 50 MB of a file are scanned.
- Watching all of `.git` means normal commits and pulls produce LOW and MEDIUM events in `.git/` (refs, logs, index).
- `storage` and `cache` are public folders, so frameworks that write compiled code there (for example Laravel's `storage/framework/views/*.php`) raise CRITICAL events for every new compiled file. Add an ignore pattern for such folders.
- A legitimate file that the baseline refuses stays out of every new baseline. Accept it once in the events list, or add an ignore pattern.

### Notes for the next build

- Do not rebuild the exe from this branch yet. The branch is not merged.
- `integrity.db` is written next to `settings.json` and is gitignored. No new dependencies.

---

## Dependency scan (branch `feature/dependency-scan`)

Goal: report known vulnerabilities (CVE / GHSA) in the packages a project depends on. Works offline after a one-time database download.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `OSVDatabase`: local SQLite copy of the OSV advisories (osv.dev) for PyPI and npm. `update()` downloads the two `all.zip` exports and rebuilds the file; it is the only code that uses the network. The new database is built beside the old one and swapped in when complete, so a failed download or a broken archive leaves the old one untouched. Stored per advisory: id, aliases (CVE), summary; per affected package: ecosystem, normalised name, severity, ranges with their events. GIT ranges and withdrawn advisories are not imported. Severity: CVSS v3 base score (computed from the vector), else the advisory's severity label, else MEDIUM. `status_warning()` reports a missing database or one older than 14 days. | `scanner_engine/deps/osv_db.py`, `scanner_engine/deps/severity.py` |
| 2 | Manifest parsers, one class each behind the ABC `ManifestParser`: `requirements*.txt`, `pyproject.toml` (PEP 621, PEP 735, Poetry tables), `Pipfile.lock`, `poetry.lock`, `package.json`, `package-lock.json` (lockfile versions 1 to 3). Every dependency carries its manifest line. `ManifestFinder` prefers lock files: `package.json` is skipped beside `package-lock.json`, `pyproject.toml` beside `poetry.lock`. Third-party folders (`node_modules`, `venv`...) are not searched. Entries installed from a URL, git or a local path are skipped. | `scanner_engine/deps/manifests.py` |
| 3 | Version matching with the OSV rule: events in version order, `introduced` switches "affected" on, `fixed` and `limit` switch it off from that version, `last_affected` after that version. PyPI versions use `packaging.version`; npm versions use the small `SemVer` class (pre-releases ordered as the semver spec says, build metadata ignored). A version that cannot be parsed is never reported. | `scanner_engine/deps/matcher.py`, `scanner_engine/deps/versions.py` |
| 4 | `DependencyScanner`. DEP001: one finding per package and vulnerability, on the manifest line, title like `Django 2.2.0: CVE-2019-14234 (SQL injection)`, fix text `Upgrade to X.Y.Z or later` with the lowest fixed version above the installed one. Records that share an id (the GHSA and the PYSEC entry of one CVE) are one finding that lists all ids. DEP002: an entry without an exact version gives one LOW finding "Unpinned dependency"; no version is guessed. Category `DEPENDENCY`. Package names are normalised (PEP 503 for PyPI). | `scanner_engine/deps/dependency_scanner.py`, `scanner_engine/categories.py` |
| 5 | Integration. `ScanOrchestrator` runs the stage only when a manifest exists; manifests count in `files_scanned`. `Issue.finding_key` keeps several vulnerabilities on one manifest line apart in `IssueMerger` and gives each its own alarm id, so a CRITICAL dependency goes through `AlarmCenter` like any other finding. A missing or old database and an unreadable manifest become engine warnings; the scan still completes. | `scanner_engine/orchestrator.py`, `scanner_engine/base.py`, `scanner_engine/issue_merger.py`, `core/alarm_center.py` |
| 6 | UI. Settings: "Update vulnerability database" button (runs in the background) and the database date; a warning when it is missing or older than 14 days. Results page: filter "Dependencies". PDF: section "Vulnerable dependencies" with package, version, ids and fix. Texts in AR/DE/EN. | `gui/pages/settings_page.py`, `gui/pages/results_page.py`, `reports/pdf_generator.py`, `translations/` |
| 7 | Config files (`.env`, `Dockerfile`, `.npmrc`, manifests, lock files, `.yaml`, `.json`...) are shown as language "Config" instead of "Unknown" in the toast and in the scan log. | `scanner_engine/base.py`, `core/alarm_center.py`, `gui/pages/scanner_page.py` |

Tests: 408 passing (226 before + 182 new). They use a tiny OSV fixture in `tests/fixtures/osv/`; no test reaches the network, and the dependency scan tests fail on any attempt to open a connection. Type check: `uvx pyright`, 0 errors.

Checked once by hand against the real OSV exports (not part of the test suite): download and import took about 54 seconds, 236,769 advisories, database file 63 MB; a scan of a small project took 0.2 seconds.

### Known limits

- Only PyPI and npm. `Pipfile` (without `.lock`), `yarn.lock`, `pnpm-lock.yaml` and `uv.lock` are not read.
- Only versions that are written in a manifest are checked. Packages that are installed but listed nowhere, and transitive packages without a lock file, are not seen.
- A package with many known vulnerabilities gives many findings (the real data lists 43 for Django 2.2.0), and the risk score then reaches 100 quickly.
- The suggested fix is the lowest fixed version above the installed one, which can be on a newer release line when the installed line got no fix.
- Advisories that list only single versions without a range, or only a GIT commit range, are not matched.
- CVSS v4 vectors are not scored; such advisories fall back to their severity label or MEDIUM.
- Advisory summaries are English only.
- The database file (`osv.db`) is written next to `settings.json`. The update replaces the whole file; there is no incremental update and no automatic update.

### Notes for the next build

- Do not rebuild the exe from this branch yet. The branch is not merged.
- New dependency in `src/requirements.txt`: `packaging`. `tomllib` and `sqlite3` are part of Python (3.11 or newer is needed for `tomllib`).
- No new PyInstaller options are expected: the new modules are plain imports. Not checked in a built exe.
- `osv.db` is not shipped. The user downloads it once from Settings.

---

## Type check, API key storage and AI privacy (branch `chore/types-and-api-key`)

Goal: a clean type check, a Gemini API key that is really saved without ever being written to a plain-text file, and no secret or unneeded code leaving the machine for the online AI.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Type check with pyright: `pyrightconfig.json` uses the project `venv` and skips `tests/corpus` (broken on purpose). 45 errors in application code fixed. `gui/dashboard.py` deleted: it imported names that do not exist and nothing used it. | `pyrightconfig.json`, 14 source files |
| 2 | `SecretStore` keeps the key in the OS credential store through `keyring` (Windows Credential Manager, service `OranovixGuardian`, entry `gemini_api_key`): `get()`, `set()`, `delete()`, `is_available()`, `mask()`. When no credential store works, `get()` returns nothing, `set()` and `delete()` raise `SecretStoreError`, and only the `GEMINI_API_KEY` environment variable is used. | `core/secret_store.py` |
| 3 | One key lookup for both AI engines: `GeminiConfig.api_key()` reads the environment variable first, then `SecretStore`. `settings.json` is no longer a key source. | `scanner_engine/gemini_config.py`, `scanner_engine/ai_analyzer.py`, `scanner_engine/ai_fix_generator.py` |
| 4 | One-time migration: an old `"api_key"` in `settings.json` is moved into `SecretStore` and deleted from the file (settings page start and every key lookup). A key already saved through the settings page is not overwritten. If the credential store is not usable, the entry stays in the file so the key is not lost, and the move is tried again next time. | `scanner_engine/gemini_config.py` |
| 5 | Settings page: Save and Remove buttons. Status shows "Key saved (••••1234)" with only the last 4 characters; the field is cleared after saving. A warning appears when the credential store is not available (Save is disabled) and a note when `GEMINI_API_KEY` is set and therefore wins. Texts in AR/DE/EN. | `gui/pages/settings_page.py`, `translations/` |
| 6 | Dead `_saved_api_key` / `_api_entry` code removed from the main window. | `gui/app.py` |

| 7 | `Redactor.redact(text)` replaces secret values with `<REDACTED>`: everything matched by the `SecretsDetector` patterns (AWS, OpenAI, GitHub, JWT with its signature, a private key block up to its END line, the password in a connection string) and any string literal assigned to or compared with a name that contains password / secret / token / api_key / secret_key and the other names of the AST secrets rule. The patterns and names are read from the scanner, not copied, so a new scanner pattern is redacted automatically. | `core/redactor.py`, `scanner_engine/secrets_detector.py`, `scanner_engine/ast_analyzer.py` |
| 8 | Every outbound AI text goes through the Redactor. The fix generator sends the title and the snippet, the analyzer sends titles and descriptions; both name the file without its folder, and the analyzer sends only the folder name of the scan target. | `scanner_engine/ai_fix_generator.py`, `scanner_engine/ai_analyzer.py` |
| 9 | A finding in the secret category never goes online (also when a secret rule was merged into it). It always gets the `OfflineFixDatabase` fix, and the analyzer leaves it out of the prompt and sends only how many there were. | `scanner_engine/ai_fix_generator.py`, `scanner_engine/ai_analyzer.py` |
| 10 | The API key is sent in the `x-goog-api-key` header; the URL has no query string. Failure messages contain only the HTTP status or the error type; analyzer errors pass through `GeminiConfig.safe_error_text`, which removes the key and any URL. | `scanner_engine/ai_fix_generator.py`, `scanner_engine/gemini_config.py` |
| 11 | Consent. Nothing is sent unless `settings.json` holds `"ai_online_consent": "allow"`; the engines check this themselves, so the default is offline even without the UI. The first AI fix that would go online opens a dialog ("The vulnerable line will be sent to Google Gemini after secrets are removed. Allow?", Allow / Use offline only). Closing the dialog saves nothing and uses the offline fix. The choice can be changed with a switch in Settings. Texts in AR/DE/EN. | `gui/ai_consent_dialog.py`, `gui/pages/results_page.py`, `gui/pages/settings_page.py`, `translations/` |
| 12 | Allowlist redaction of code, because a pattern list cannot know every secret format. `Redactor.redact_code(snippet, file_name)`: (a) the content of every string literal becomes `<STR_1>`, `<STR_2>`... with the same value always getting the same placeholder; quotes and prefixes stay; only empty strings, single characters and single escapes are kept. Handles `'`, `"`, triple quotes, `r`/`b`/`f` prefixes, JS template strings, C# `$"..."` and `@"..."`, PHP/Java/C# quotes; in f-strings and template strings the `{...}` fields stay as code. An unterminated string is redacted to the end of the line. (b) Outside strings, every token of 16+ characters that mixes letters and digits becomes `<VALUE_1>`..., except a name that is being called (`get_object_or_404(`). (c) Comment text becomes `<COMMENT>`; the file extension decides whether `#` or `//` starts a comment. (d) The pattern pass from step 7 runs over the result as a second layer. Titles and descriptions use `redact` (patterns, then long tokens). The prompt tells the model to keep the placeholders; the returned fix is shown as it is and real values are never put back. | `core/redactor.py`, `scanner_engine/ai_fix_generator.py` |

Tests: 226 passing (117 + 25 in `tests/test_secret_store.py` + 84 in `tests/test_ai_privacy.py`). The key tests use an in-memory keyring backend and never touch the real Credential Manager; the privacy tests replace the HTTP call and inspect the request, so no test reaches the network. Type check: `uvx pyright`, 0 errors.

### Notes for the next build

- New dependency: `keyring` (`src/requirements.txt`).
- PyInstaller needs: `--hidden-import keyring.backends.Windows`.
- Not checked in a built exe yet. If the exe reports "secure storage is not available", also add `--copy-metadata keyring`.

### Known limits

- A new key is used by the next AI request; no restart is needed. An AI request that is already running keeps the old key.
- The settings page does not test the key against Google; a wrong key shows up at the first AI request.
- Code redaction is deliberately broad. The model no longer sees what a string says (for example the SQL text), only that there is a string and how it is combined with variables, so an online fix can be less specific than before.
- In a settings file (`.env*`, `.ini`, `.cfg`, `.conf`, `.properties`, `.yaml`, `.yml`, `.toml`) every unquoted value after `=` or `:` is replaced too, except booleans and numbers.
- Still sent as they are: variable and function names, numbers, and, in source files, values outside strings that are shorter than 16 characters or have no digit (for example a password typed unquoted in a shell script).
- Titles and descriptions are prose and only get the pattern and long-token passes, not the string replacement.
- With the offline choice or without consent, the AI fix button still works and shows the offline fix.

---

## Phase 1 — Django and DRF rules (branch `feature/django-rules`)

Goal: find the typical Django mistakes with few false alarms. Rules that depend on user input use a taint tracker instead of pattern matching. Python `ast` only, no new dependencies.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | `TaintTracker`, one per function. Sources: `request.GET`, `POST`, `data`, `query_params`, `body`, `COOKIES`, `META`, `FILES`. Taint flows through assignment, subscript, `.get()`, concatenation, f-strings, `%` and `.format()`. Cleared by `int()`, `float()`, `uuid.UUID()`, `os.path.basename()`, `get_valid_filename()`, `escape()`, by a `url_has_allowed_host_and_scheme` check and by `name in ALLOWLIST`. Flow-sensitive: an expression is judged with the state at its own statement. | `scanner_engine/taint.py` |
| 2 | View rules, one class per rule (`DjangoRule.check(tree, tracker)`): DJ001 `@csrf_exempt` (HIGH), DJ002 SSRF (CRITICAL), DJ003 open redirect (HIGH), DJ004 path traversal (CRITICAL), DJ005 reflected XSS (HIGH), DJ006 raw SQL (CRITICAL), DJ007 JWT without signature check (CRITICAL), DJ008 DRF `AllowAny` on a write view (HIGH), DJ009 serializer `fields = "__all__"` (MEDIUM), DJ010 possible IDOR (HIGH, confidence LOW). | `scanner_engine/django_rules.py` |
| 3 | Settings rules, only for `settings.py` and files directly inside `settings/`: DS001 `ALLOWED_HOSTS` with `"*"` (HIGH), DS002 secure cookies off or missing (MEDIUM), DS003 `CsrfViewMiddleware` missing (HIGH), DS004 `SecurityMiddleware` missing (MEDIUM), DS005 `CORS_ALLOW_ALL_ORIGINS = True` (HIGH), DS006 SSL redirect / HSTS missing (LOW). "Missing" is only reported for a complete settings module, not for a file that star-imports a base module. | `scanner_engine/django_settings_rules.py` |
| 4 | Template rules for `.html`: DT001 `\|safe` (MEDIUM), DT002 `{% autoescape off %}` (HIGH). | `scanner_engine/django_template_rules.py` |
| 5 | Integration. View and settings rules run inside `PythonScanner`; templates run as their own `ScanOrchestrator` stage and count in `files_scanned`. Every rule has an `IssueCategory`, so a DJ finding merges with Bandit on the same line (DJ006 + B608). A merged issue keeps the highest confidence and the help text of any engine in the group. 18 `VulnerabilityDatabase` entries (what, why, how exploited, fix with code). `AlarmCenter`: sound and taskbar flash only for CRITICAL with confidence not LOW; LOW confidence gets a "needs review" badge on the results page and a toast, never a sound. Badge, hint, alarm title and rule titles are translated (AR/DE/EN). | `scanner_engine/python_scanner.py`, `scanner_engine/orchestrator.py`, `scanner_engine/issue_merger.py`, `scanner_engine/categories.py`, `scanner_engine/vulnerability_db.py`, `core/alarm_center.py`, `core/language_manager.py`, `gui/pages/results_page.py`, `translations/` |
| 6 | Corpus `tests/corpus/django_app/` (views, vulnerable and hardened settings, two templates). Every rule has at least one vulnerable case that must be reported and one safe case that must not. | `tests/test_django_rules.py` |

Tests: 117 passing (28 from Phase 0 + 89 new).

### Known limits

- Taint is tracked inside one function. It does not follow a value into a helper function, through `self.x`, or out of a nested function.
- A call to an unknown function does not carry taint (`requests.get(build_url(host))` is not reported). Methods called on tainted data and a short list of string and path helpers do.
- The Secure-cookie and HTTPS checks cannot see settings that live in another file unless that file is star-imported.
- Bandit still reports B608 for an f-string query whose only variable went through `int()`. It arrives with LOW confidence, so it shows the "needs review" badge and stays silent.
- Vulnerability help texts are English only; titles and the badge are translated.

### Notes for the next build

- Do not rebuild the exe from this branch yet. The branch is not merged.
- No new PyInstaller options are needed: the new modules are plain imports.

---

## Phase 0 — Engine Foundation (branch `fix/engine-foundation`)

Goal: make the scan engine trustworthy before adding features. Engine first, UI last.

| Step | Change | Main files |
|------|--------|-----------|
| 1 | Every language in a folder is scanned. `ScannerFactory.scanners_for_target` returns one scanner per language present; `ScanOrchestrator` runs language scanners + `SecretsDetector` + `RuleEngine` and returns one merged `ScanResult`. The scanner page only calls the orchestrator. | `scanner_engine/orchestrator.py`, `scanner_engine/factory.py`, `gui/pages/scanner_page.py` |
| 2 | Third-party folders are skipped by every engine through one shared `EXCLUDED_DIRS` (venv, .venv, env, node_modules, `__pycache__`, .git, dist, build, site-packages, migrations). | `scanner_engine/base.py` |
| 3 | Bandit runs as a library (`BanditRunner`) on the already filtered file list. If it cannot load or run, `ScanResult.engine_warnings` is filled and shown in the scan log, status bar and PDF. | `scanner_engine/bandit_runner.py`, `scanner_engine/python_scanner.py`, `reports/pdf_generator.py` |
| 4 | Duplicates are merged. Every rule has an `IssueCategory`; `IssueMerger` merges issues with the same (file, line, category), keeps the highest severity and stores the other rule ids in `Issue.also_detected_by`. Title "Hardcoded Hardcoded Password" fixed. | `scanner_engine/categories.py`, `scanner_engine/issue_merger.py` |
| 5 | False positives cut. SEC002 (regex `open()` path traversal) is disabled until it returns as a taint rule. RULE-002 ignores `127.0.0.1`, `0.0.0.0` and version strings (`Rule.exclude_line_pattern`). | `scanner_engine/python_scanner.py`, `scanner_engine/rule_engine.py`, `rules/default_rules.json` |
| 6 | Score no longer saturates: `weighted = 40*C + 20*H + 5*M + 1*L`, `score = round(100 * (1 - 0.5 ** (weighted / 40)))`. Labels unchanged; raw counts (`C:3 H:1 M:0 L:2`) are shown next to the score. | `scanner_engine/base.py` |
| 7 | Central alarm. `AlarmCenter.notify(findings)`: CRITICAL → critical sound + red toast + taskbar flash; HIGH → toast only. Stable finding id = sha1(category + relative path + line), stored in SQLite so a finding never alarms twice. Channels are injected so a background monitor can reuse it. Text in AR/DE/EN. | `core/alarm_center.py`, `gui/alarm_channels.py` |
| 8 | pytest suite (no GUI) with a vulnerable corpus in `tests/corpus/`. Run: `venv\Scripts\python -m pytest`. | `tests/`, `pytest.ini`, `src/requirements-dev.txt` |
| 9 | Repo cleanup: `release/` untracked and ignored; Gemini model read from `settings.json` (`gemini_model`, default `gemini-flash-latest`); a 404 gives a clear message. | `.gitignore`, `scanner_engine/gemini_config.py` |

### Follow-up fixes

| Fix | Change | Main files |
|-----|--------|-----------|
| 1 | Dotfiles are scanned again. `FileMatcher` matches by suffix **or** by name, so `.env`, `.env.local`, `.env.production` are found (`Path(".env").suffix` is empty). `SecretsDetector` also scans `Dockerfile`, docker-compose files, `.htpasswd`, `.npmrc`, `.pypirc`. `files_scanned` counts every file any engine looked at. | `scanner_engine/base.py`, `scanner_engine/secrets_detector.py`, `scanner_engine/orchestrator.py` |
| 2 | The alarm no longer goes silent forever. Sound + flash still fire once per finding, but every scan with open CRITICAL findings shows a persistent red banner on the results page ("N critical findings still open"). A full scan removes ids from `alarmed_findings` that are no longer present in that root, so a fixed-then-reintroduced finding alarms again. Finding ids are scoped to the scan root. | `core/alarm_center.py`, `gui/pages/results_page.py` |
| 3 | Readable titles. Bandit ids map to clear titles (`B307` → "Use of eval()", `B301` → "Unsafe pickle deserialization", ...). A merged issue led by Bandit takes the title of our own rule when one matched. | `scanner_engine/python_scanner.py`, `scanner_engine/issue_merger.py` |
| 4 | Local tool folders are ignored through `.git/info/exclude` (local only) instead of `.gitignore`. | `.gitignore` |

Tests: 28 passing (`venv\Scripts\python -m pytest`).

### Notes for the next build

- Do not rebuild the exe from this branch yet.
- Bandit now loads its checks as plugins, so PyInstaller needs:
  `--collect-all bandit --collect-all stevedore --copy-metadata bandit`.
  `bandit.exe` no longer has to be bundled.
- Score reference points: 1 low = 2, 1 high = 29, 1 critical = 50, 2 criticals = 75, 3 criticals = 88, 8 or more criticals round to 100.

### Open items

- ~~SEC002 path traversal returns as a taint-tracking rule.~~ Done as DJ004 in Phase 1.
- Background monitor that feeds `AlarmCenter.notify`.
- Dashboard history still shows the score without the raw counts.

---

## v1.1.0 — Advanced Features Release

### Feature 1: Secrets Detection ✅
**File:** `scanner_engine/secrets_detector.py`

- Abstract base class `SecretPattern(ABC)` with `pattern`, `secret_type`, `severity` abstract properties
- 7 concrete pattern classes: `AWSKeyPattern`, `OpenAIKeyPattern`, `GitHubTokenPattern`, `PasswordPattern`, `ConnectionStringPattern`, `PrivateKeyPattern`, `JWTPattern`
- `SecretsDetector(BaseScanner)` scans **every** text file type regardless of language (40+ extensions)
- Secrets values are masked in the UI (shows only first 6 + last 4 chars)
- Integrated into `scanner_page.py` as Phase 2 of the scan pipeline
- Results de-duplicated by `(rule_id, file_path, line_number)` before merging

---

### Feature 2: AST Parsing (Python) ✅
**File:** `scanner_engine/ast_analyzer.py`

- Abstract base class `ASTRule(ABC)` with `check(node: ast.AST)` abstract method
- 5 concrete rule classes:
  - `DangerousFunctionRule` — detects `eval()`, `exec()`, `compile()` calls
  - `SQLInjectionRule` — detects f-string/`.format()`/concatenation inside `cursor.execute()`
  - `HardcodedSecretsRule` — detects string literals assigned to sensitive variable names
  - `InsecureImportRule` — detects `import pickle`, `import marshal`, `import shelve`
  - `WeakCryptoRule` — detects `hashlib.md5()`, `hashlib.sha1()`
- `ASTAnalyzer.analyze(code, file_path)` classmethod — zero external dependencies
- Integrated into `PythonScanner._do_scan()` after Bandit + regex checks
- Full de-duplication against Bandit findings

---

### Feature 3: AI Fix Generator ✅
**File:** `scanner_engine/ai_fix_generator.py`

- `FixSuggestion` dataclass: `original_code`, `fixed_code`, `explanation`, `prevention`, `confidence`, `source`
- `OfflineFixDatabase` — 14 curated fix templates covering: SQL injection, eval/exec, passwords, MD5/SHA1, pickle, os.system, AWS/GitHub/OpenAI keys, JWT, path traversal, and more
- `AIFixGenerator` — Gemini REST API integration with automatic offline fallback
  - API key resolved from: constructor → `settings.json` → `GEMINI_API_KEY` env var
  - Memory cache avoids repeated API calls for the same issue
  - `generate_fix_async()` — non-blocking background thread delivery
- UI integration in `IssueAccordion._build_detail()`:
  - "🤖 AI Fix" button in every issue's detail panel
  - Shows loading indicator while generating
  - Displays source badge (Gemini AI / Offline), confidence %, fixed code, explanation, prevention
  - "📋 Copy Fix" button copies fixed code to clipboard
  - Syntax-highlighted fixed code block (Consolas font, green-on-dark)

---

### Feature 4: Rule Engine ✅
**File:** `scanner_engine/rule_engine.py`

- `RuleLanguage(str, Enum)` — `ALL`, `Python`, `JavaScript`, `PHP`, `Java`, `C#`
- `Rule` dataclass: `id`, `name`, `description`, `pattern`, `severity`, `language`, `enabled`, `fix_suggestion`, `is_builtin`
- `RuleEngine` class:
  - Loads from `rules/default_rules.json` (built-in) + `rules/custom_rules.json` (user)
  - `add_rule()`, `enable_rule()`, `disable_rule()`, `delete_rule()` — all persist automatically
  - `scan(code, language)` and `scan_file(file_path, language)` — return `Issue` objects
  - `test_rule(rule, sample_code)` — test without persisting
  - `export_rules(path)` / `import_rules(path)` — JSON import/export
- **10 built-in default rules:**
  1. TODO Security Comment
  2. Hardcoded IP Address
  3. Disabled SSL/TLS Verification
  4. Debug Mode Enabled (Python)
  5. Weak Random for Security (Python)
  6. Insecure HTTP URL
  7. console.log of Sensitive Data (JavaScript)
  8. Overly Permissive CORS
  9. Sensitive Data in URL Parameter
  10. PHP Short Open Tags
- UI: **Rules Manager** section in Settings page:
  - Scrollable list of all rules with ON/OFF toggle per rule
  - Severity badge (colored) and language tag per rule
  - Built-in rules marked as "built-in" (cannot delete, only toggle)
  - Custom rules have a delete (✕) button
  - "Add Rule" button opens a dialog with: ID, Name, Description, Pattern, Severity dropdown, Language dropdown, Fix Suggestion, and a live Test area
  - "Import Rules" / "Export Rules" buttons (JSON file)
  - Rule count indicator ("X/Y rules active")
- Integrated into `scanner_page.py` as Phase 3 of the scan pipeline

---

### Scanner Pipeline (Updated)

Each scan now runs 3 phases:

1. **Language Scanner** (Bandit + regex + AST for Python; regex for JS/PHP/Java/C#)
2. **Secrets Detector** (all file types, 7 secret patterns)
3. **Rule Engine** (user-defined + built-in regex rules)

All results are de-duplicated by `(rule_id, file_path, line_number)` before display.

---

### Files Changed

| File | Change |
|------|--------|
| `scanner_engine/secrets_detector.py` | **NEW** |
| `scanner_engine/ast_analyzer.py` | **NEW** |
| `scanner_engine/ai_fix_generator.py` | **NEW** |
| `scanner_engine/rule_engine.py` | **NEW** |
| `rules/default_rules.json` | **NEW** |
| `rules/custom_rules.json` | **NEW** |
| `scanner_engine/__init__.py` | Updated exports |
| `scanner_engine/python_scanner.py` | ASTAnalyzer integration in `_do_scan` |
| `gui/pages/scanner_page.py` | Phase 2+3 scan pipeline, new imports |
| `gui/pages/results_page.py` | AI Fix button in IssueAccordion |
| `gui/pages/settings_page.py` | Rules Manager section |
| `translations/en.json` | 20 new translation keys |
| `PROGRESS.md` | **NEW** |

---

### v1.0.0 — Initial Release

- Python scanner (Bandit + regex SEC001/SEC002)
- JavaScript/TypeScript scanner (15 rules)
- PHP scanner (12 rules)
- Java scanner (12 rules)
- C# scanner (13 rules)
- Vulnerability database (CWE/OWASP education)
- CustomTkinter GUI (Dark/Light theme, 10 languages)
- PDF report generation (ReportLab)
- Scan history (SQLite)
- AI analysis (Gemini API, optional)
- Sound alerts (Windows winsound)
