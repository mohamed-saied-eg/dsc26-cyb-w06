# dsc26-cyb-w06 · Hisn copilot input and output guard

DSC Summer Internship 2026 · Cybersecurity track · Week 6 (Securing LLM features)
**Python 3.12 · pytest 9.1.1 · standard library only** · expected time 3 to 4 hours · everything runs offline

## Scenario

Hisn's AI pod has a triage prompt that works on clean alerts. Karim will not let it near the night
shift until the Cyber pod has built the guard around it: normalise and scan untrusted text, build the
model input safely, and check every reply before an analyst sees it. You build `copilot_guard`. There
is no model in this task; replies are fixtures, as they would be in a regression suite.

## Set up

1. On GitHub create a **public** repository in your own account named exactly `dsc26-cyb-w06`, with no README.
2. Unzip this starter into a folder called `dsc26-cyb-w06`, then:

```bash
git init -b main
uv venv --python 3.12
source .venv/bin/activate            # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt   # pinned versions; you cannot add packages
python -m pytest -q                  # the 5 public tests fail until you build the task
git add . && git commit -m "chore: starter from DSC"
git remote add origin https://github.com/<your-username>/dsc26-cyb-w06.git
git push -u origin main
```

Always run tests with `python -m pytest` from the repository root, the way the grader does. Do not
edit anything under `fixtures/`; the grader replaces it with DSC's copy before scoring.

## Files

```
copilot_guard/__init__.py
copilot_guard/normalize.py   # part 1
copilot_guard/prompt.py      # part 2
copilot_guard/output.py      # part 3
fixtures/alert_ssh_bruteforce.json
fixtures/alert_injected_useragent.json
fixtures/benign/lines.txt
tests/test_public.py
AI_USAGE.md                  # fill in before you submit (the grader checks the headings)
requirements.txt
```

Keep the names and signatures exactly as they are in the starter: the grader imports them. The
dataclasses, `Rejected`, constants and regex pattern strings are already written; the functions raise
`NotImplementedError`.

## What to build

### 1. `copilot_guard/normalize.py`

```python
def has_hidden_characters(text: str) -> bool: ...
def normalize(text: str) -> str: ...
def detect_injection(text: str) -> list[str]: ...
```

- **Hidden characters**: U+200B, U+200C, U+200D, U+2060, U+FEFF, U+00AD; bidi controls U+061C, U+200E,
  U+200F, U+202A-U+202E, U+2066-U+2069; and the Tags block U+E0000-U+E007F.
- **`normalize`**: remove hidden characters, apply Unicode NFKC, remove Arabic tatweel (U+0640) and
  marks U+064B-U+065F and U+0670, casefold, collapse all whitespace runs to one space and strip.
- **`detect_injection`**: a sorted list of signal codes. `hidden_characters` if the *original* text has
  any hidden character. The other codes are searched in the *normalised* text with the exact regular
  expressions already in `PATTERNS` in the starter (`override`, `role_tag`, `action_request`,
  `exfil_markup`). Do not add patterns of your own: this task is about normalising and handling output
  correctly, not about inventing a better keyword list, and the hidden false-positive test is private.

### 2. `copilot_guard/prompt.py`

```python
def build_messages(alert: dict, tenant_id: str, nonce: str) -> list[dict]: ...
```

- `nonce` must be 16-64 lowercase hex characters and `tenant_id` must match `TEN-` + 3 digits, else
  raise `ValueError`.
- Keep only `ALLOWED_FIELDS` that are present in `alert` and not `None`; cut `full_log` to its first
  `MAX_LOG_CHARS` (4,000) characters.
- Return two messages, each `{"role": ..., "content": ...}`. The system message names the tenant id
  and the nonce and says the tagged content is data; it contains no alert data. The user message is
  exactly `f"<alert-{nonce}>\n{body}\n</alert-{nonce}>"`, where `body` is
  `json.dumps(data, ensure_ascii=False, sort_keys=True)` with every `<` replaced by `<` and every
  `>` replaced by `>` (still valid JSON, same value, but the data can never contain the literal
  closing tag).

### 3. `copilot_guard/output.py`

```python
def parse_model_output(raw: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult: ...
def triage(alert: dict, raw_output: str, *, tenant_id: str, known_alert_ids: set[str]) -> TriageResult: ...
```

`parse_model_output`, in this order:

1. Strip the reply. If it is a fenced block (` ```json ` or ` ``` ` on the first line, ` ``` ` on the
   last), take the inside. It must then parse as a JSON object, else `Rejected("not_json")`.
2. Any key `action`, `actions`, `tool_call`, `tool_calls` or `function_call`, or a `next_step` that is a
   string containing `close`: `Rejected("forbidden_action")`.
3. `severity` not in `SEVERITIES`: `Rejected("bad_severity")`. `next_step` not in `NEXT_STEPS`:
   `Rejected("bad_next_step")`. `summary` not a string, blank, or longer than 600 characters after
   stripping: `Rejected("bad_summary")`. `related_alert_ids` (missing means `[]`) not a list of
   strings: `Rejected("bad_related_alert_ids")`.
4. The summary mentions any `TEN-` + 3 digits other than `tenant_id`: `Rejected("cross_tenant_reference")`.
5. Related ids: remove duplicates (keep first), drop ids not in `known_alert_ids`, and add flag
   `unknown_alert_id` if any were dropped.
6. Summary clean-up on the stripped text: every markdown image `![...](...)` becomes `[image removed]`
   (flag `image_removed`); every markdown link `[text](url)` whose URL host is not exactly in
   `ALLOWED_LINK_HOSTS` (scheme `http` or `https`, host from `urlsplit(url).hostname`) becomes just
   `text` (flag `link_removed`); every bare `http://` or `https://` URL outside a kept link whose host
   is not allowed becomes `[link removed]` (flag `link_removed`). Then `html.escape(summary, quote=True)`.
7. Flags are sorted and unique.

`triage`: run `detect_injection` on every string in the alert (keys and values, nested). If there are
any signals, add flag `possible_injection` and one `signal:<code>` flag per code, raise severity to at
least `high` (never lower it), and change a `monitor` next step to `escalate_to_analyst`. Errors from
parsing propagate as `Rejected`.

## Starter files DSC provides

- `fixtures/alert_ssh_bruteforce.json`: a benign Wazuh-style alert, including a `client_api_key` field
  the integration adds for its own use — it has no business in a prompt.
- `fixtures/alert_injected_useragent.json`: a web alert whose User-Agent carries an override attempt
  with a zero-width space inside "IGNORE".
- `fixtures/benign/lines.txt`: 20 ordinary Wazuh, nginx and Windows log lines in English and Arabic,
  for your own false-positive checks. With a correct implementation exactly one is flagged (a Windows
  event containing `System:`, which matches the `role_tag` pattern) — that is a known false positive,
  not a bug.

## Public tests

`tests/test_public.py`: a zero-width override, the alert wrapped so it cannot close the tag, a forbidden
`close_alert` rejected, a markdown image removed and HTML escaped, and an injected alert that cannot
talk its way down to `low`/`monitor`. They are a smoke test, not the grade.

## How grading works

1. Push, then press **Submit for grading** on DSC Hex. The grader pins your latest commit, clones it,
   replaces your `fixtures/` with DSC's copy, copies in DSC's hidden tests and runs
   `python -m pytest -q -p no:cacheprovider --timeout=20 tests_hidden/` from the repository root with
   Python 3.12, the pinned packages and the network off: 20 seconds per test, 3 minutes in total. If
   the whole run passes 3 minutes, no test is credited.
2. Before the run the grader deletes any root `conftest.py`, ignores pytest settings in config files,
   and removes top-level files that would shadow a standard-library or test-tool module. Keep your code
   inside `copilot_guard/`.
3. If `AI_USAGE.md` is missing or lacks any of the headings `## Tools`, `## What AI got wrong`,
   `## In my own words`, the grader stops and scores 0 with that reason.
4. You get a score from 0 to 100 and, per hidden test, its public name, pass or fail and a short hint.
   Each ID passes only if every case under it passes. A hidden test that cannot import a name fails on
   its own; the others still run. Property tests use fixed seeds, so the same code always gets the
   same score.
5. 5 grader runs per task per day. Late policy: ×1.0 within 72 hours of the W6 session starting, ×0.6
   for the following 7 days, ×0.5 after that until the programme's final grading date.

### Hidden tests

| ID | Public name | What it checks | Weight |
|---|---|---|---|
| H01 | normalise: invisible, full-width, case and spaces | Zero-width joiner, soft hyphen, BOM, tag characters removed; `ｉｇｎｏｒｅ` → `ignore`; `ß` casefolds to `ss`; tabs and newlines collapse | 8 |
| H02 | normalise: Arabic tatweel and harakat | `تجـــاهل التعليمات` and `تَجاهَل جميع التعليمات` normalise and trigger `override` | 6 |
| H03 | detect: every signal in the table | At least two positive cases per code, after obfuscation | 10 |
| H04 | detect: no matches beyond the table | 30 private benign lines (SSH, nginx, Windows events, Arabic user names, a URL with `/system/` in the path, the word "ignore" in a file name): only the lines the patterns genuinely match are flagged, with exactly the expected codes | 8 |
| H05 | hidden characters alone are a signal | A tag-character payload inside an innocent string; a bidi override; a lone zero-width space | 4 |
| H06 | input: only what the model needs | Bad nonce (uppercase, 15 chars, non-hex) and bad tenant raise; only allowed fields; `None` dropped; `full_log` cut at 4,000; the system message carries no alert data | 8 |
| H07 | input: the delimiter cannot be closed | Property test with `<`, `>`, the nonce and `</alert-...>` in the data: the body never contains `<` or `>`, and `json.loads(body)` equals the filtered alert | 10 |
| H08 | output: JSON object or nothing | Both fence styles accepted; JSON inside prose, a list, and plain text are `not_json` | 6 |
| H09 | output: forbidden actions and field rules | `tool_call` key, `auto_close`-style step, bad severity, bad step, summary of 600 vs 601 characters, ids not a list | 8 |
| H10 | output: no images, no foreign links | Image removed; allowed link kept; a look-alike host, a userinfo trick, `javascript:` and bare foreign URLs removed; flags set | 10 |
| H11 | output: other tenants are never mentioned | Another tenant id in a summary is rejected; the tenant's own id is fine | 4 |
| H12 | output: related ids are real and unique | Unknown ids dropped and flagged; duplicates removed in order | 4 |
| H13 | triage: signals never lower the bar | Injected alert raised to `high`; `critical` stays `critical`; `monitor` becomes `escalate_to_analyst`; signal flags listed; a benign alert passes through unchanged | 10 |
| H14 | output: safe to render | Quotes and ampersands escaped; no raw `<` in `summary_html` for any accepted reply | 4 |
| | | **Total** | **100** |

**Anti-cheating notes.** H04 and H13 use private alerts and log lines, so a detector tuned only to the
two public fixtures, or one that matches before normalising or without word boundaries, loses the
false-positive test. H07 is a property test. The patterns are fixed by the spec on purpose: do not add
patterns of your own.

## AI tools

AI tools are allowed. `AI_USAGE.md` must keep its three headings (`## Tools`, `## What AI got wrong`,
`## In my own words`). Under `## In my own words`, answer in one or two sentences each, without AI:

1. Which leg of the lethal trifecta does stripping markdown images remove, and why does that matter for Hisn?
2. Why does `triage` raise the severity of an alert that contains an injection attempt instead of just warning?

The grader does not score the content, but it scores 0 if the file or a heading is missing. Assistants
tend to write a naive keyword filter and skip normalisation first, or render the model's reply with
`| safe` — exactly what this task's hidden tests catch.

## Rules

- Defensive and offline. Standard library only; you cannot add packages. There is no live model in
  this task; everything is fixtures.
