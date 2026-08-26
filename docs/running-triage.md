# Running a triage

The notebook is the intended interface: an analyst opens it, pulls a window of recent
mail, and reads verdicts. The analysis itself lives in `src/soc_triage/`, so you can
drive it from your own code just as easily — see [Without the notebook](#without-the-notebook).

```bash
az login
source .venv/bin/activate
jupyter lab notebooks/01_triage.ipynb
```

`az login` matters: with `ANTHROPIC_FOUNDRY_API_KEY` blank, the agent calls Foundry as
**you**, and Foundry's audit log and Sublime's access justification both name the human
who ran the triage.

---

## The notebook, section by section

### 1 · Connect

Builds a `TriageSession` and renders `settings.describe()` as a table. Read the last two
rows before anything else:

```
Mailbox actions        disabled (read-only)
VT submission          disabled (lookup only)
```

If either says `ENABLED`, know why before you continue.

A rendered table means your configuration parsed. It does not mean any credential is
valid — the first live call is in section 2.

### 2 · Pull recent messages

```python
LOOKBACK_MINUTES = 5      # widen to 60 / 1440 in a low-volume test tenant
INBOUND_ONLY = True       # exclude your own outbound and internal mail
```

Calls `GET /v0/message-groups/search` over a `created_at` window — `start` inclusive,
`end` exclusive, so a message never lands in two consecutive windows. Returns a table of
message id, timestamp, sender, subject, mailbox, which Sublime rules flagged it, group
size and user reports.

**An empty result is the normal first experience.** Five minutes is the right default for
the monitoring use case and a poor default for a demo tenant. Set `LOOKBACK_MINUTES =
1440` and re-run the cell.

### 2b · Look up a specific person

```python
IDENTIFIER = 'alice@corp.com'   # or a display name: 'Jane Doe'
LOOKBACK_DAYS = 7
```

The analyst-driven entry point. `GET /v0/message-groups/search` filters on `created_at`
only, so an identifier has to go through a hunt — the cell generates MQL and posts it to
`POST /v0/hunt-jobs`, then polls until the job completes.

- An identifier containing `@` is matched **exactly** against `sender.email.email`,
  `recipients.to` and `recipients.cc`.
- Anything else is treated as a display name and matched as a **case-insensitive
  substring** against `sender.display_name` and recipient display names, because analysts
  type `Jane Doe` when the header carries `Jane Doe (Finance)`.

The generated MQL is printed above the results — read it before trusting what comes back.
Results land in `messages`, so section 3 triages them with no change. Leave `IDENTIFIER`
empty to skip the cell and keep the section 2 results.

Hunts are asynchronous and this call blocks, bounded at 60s by default. If a hunt is still
running when that elapses, the raised error carries the job id so you can collect it later
with `session.sublime.get_hunt_results(job_id)`.

### 3 · Triage

```python
TARGET_IDS = [m['message_id'] for m in messages][:10]
results = await session.triage_many(TARGET_IDS, concurrency=3)
```

`concurrency=3` is deliberate, not timid: pay-as-you-go Foundry quota for Claude is
**40 RPM / 40K input tokens per minute**, and each triage makes several tool-augmented
calls carrying raw EML and the Sublime message data model. Raising it is the fastest way
to start collecting 429s.

Expect **30–90 seconds per message**. What the agent does with that time:

| Tool | What it gets |
|---|---|
| `get_message_content` | Subject, sender, recipients, body — wrapped in untrusted-content markers |
| `analyze_email_authentication` | SPF/DKIM/DMARC, Received chain, display-name spoofing, punycode and Cyrillic lookalikes — computed in Python, handed over as fact |
| `extract_indicators` | URLs, domains, IPs, hashes; defanged, deduplicated, quota-prioritized |
| `get_sublime_verdict` | Sublime's own ML attack score and the rules that flagged it |
| `check_link_reputation` | Sublime ML link analysis for a specific URL |
| `virustotal_lookup` | Existing VT report for an indicator. Lookup only — never submission |
| `hunt_related_messages` | MQL hunt for the same indicator across historical mail → blast radius |
| `validate_detection_rule` | Syntax-validates a proposed MQL rule via `POST /v0/rules/validate` |
| `action_message` | **Only registered when `ALLOW_MAILBOX_ACTIONS=true`** |

The result is constrained to a Pydantic schema, so nothing downstream parses prose.

**Escalation** to `claude-opus-5` fires when any of these hold, and the second pass is
explicitly told not to rubber-stamp the first:

- severity is `malicious` or `critical`
- confidence is below 0.65
- the verdict disagrees with Sublime's attack score
- a prompt injection attempt was detected

Low confidence counts as much as high severity — an uncertain call on a benign-looking
message is exactly where a stronger second pass pays off.

### 4 · Read the reports

Sorted by severity then confidence. Each verdict renders as an HTML card. What to look at
first, in order:

1. **Disagreement with Sublime.** A second opinion that always agrees is worthless; the
   disagreements are where a human should look first.
2. **Prompt injection detected.** The email tried to manipulate the agent. That is itself
   a malicious indicator, and the excerpt is in the verdict.
3. **Users who clicked.** Mailboxes with recorded link clicks are a confirmed incident,
   not a triage item.
4. **Campaign scope.** Blast radius from the hunt — how many related messages and
   mailboxes.
5. **Confidence.** Below ~0.65 the model already escalated; if it is still low, that is
   the model telling you it needs a human.

Indicators are **defanged** (`hxxp://`, `[.]`) and every one carries a rationale and a
source (`virustotal`, `sublime_link_analysis`, `header_analysis`, …). Attacker-controlled
strings are HTML-escaped on the way into the report — that is one of the things the test
suite covers.

The next cell writes Markdown copies to `reports/` for ticketing:

```python
path = save_report(result, settings.report_dir)
```

**`reports/` contains real message content** and is gitignored. So are notebook outputs —
a saved `.ipynb` embeds message bodies, recipient addresses and IOCs. Clear them before
sharing:

```bash
jupyter nbconvert --clear-output --inplace notebooks/*.ipynb
```

### 5 · Response actions — human in the loop

Lists everything with severity `malicious` or above and prints the exact call for each:

```
CRITICAL   quarantine       94%  Urgent: review the attached invoice
           session.sublime.action_message("01HX...", "quarantine")
```

It prints; it does not run. You copy the line for the message you decided on and execute
it yourself. There is deliberately no "apply all" — each action is an individual
decision, and `action_message` is not even registered as a tool unless
`ALLOW_MAILBOX_ACTIONS=true`.

Dispositions the model can recommend: `no_action`, `monitor`, `quarantine`, `trash`,
`escalate_to_ir`.

### 6 · Triage an arbitrary message

Paste a message id — from a Sublime dashboard URL or a user report — and triage it
directly, with a justification recorded against your identity:

```python
MESSAGE_ID = '01HX...'
result = await session.triage(
    MESSAGE_ID,
    justification='Analyst-initiated review of user-reported message',
)
```

This cell also prints the ordered list of tool calls the agent made. That is the audit
trail: it shows what evidence the verdict was actually built from.

### 7 · Close

```python
session.close()
```

Closes the Sublime and VirusTotal HTTP clients. `TriageSession` is also a context
manager if you prefer `with`.

---

## Without the notebook

`TriageSession` is plain async Python with no notebook dependency:

```python
import asyncio
from soc_triage.config import load_settings
from soc_triage.triage import TriageSession
from soc_triage.report import render_markdown

async def main():
    with TriageSession(load_settings()) as session:
        messages = session.recent_messages(lookback_minutes=1440)
        ids = [m["message_id"] for m in messages][:5]

        for result in await session.triage_many(ids, concurrency=3):
            if not result.ok:
                print(f"{result.verdict.message_id}: FAILED — {result.error}")
                continue
            v = result.verdict
            print(f"{v.severity.value:<10} {v.confidence:.0%}  {v.subject[:60]}")
            if v.disagrees_with_sublime:
                print(f"  ⚠ disagrees with Sublime: {v.disagreement_note}")
            print(render_markdown(result))

asyncio.run(main())
```

Useful knobs on `triage()`:

| Argument | Default | Effect |
|---|---|---|
| `justification` | `"Automated SOC triage review (analyst-initiated)"` | Recorded with Sublime before message content is unredacted. Make it meaningful. |
| `allow_escalation` | `True` | `False` pins triage to the primary model — useful for cost-bounded batch runs. |
| `effort` | `"high"` | Reasoning effort passed through to the model. |

`triage_many()` never raises for a single bad message: failures come back as
`TriageResult` objects with `ok == False` and the reason in `.error`, so one unreadable
message cannot abort a batch. Always check `.ok` before touching `.verdict`.

The original brief asked for a five-minute polling trigger, and this is where it would
go: a loop around `recent_messages()` and `triage_many()` plus a cursor store. A Sublime
webhook is the better trigger. See
[Known limits](../README.md#known-limits).
