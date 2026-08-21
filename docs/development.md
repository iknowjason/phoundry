# Development

## Layout

```
src/soc_triage/
  config.py       Settings + safety switches (default closed)
  models.py       TriageVerdict — the structured output contract
  sublime.py      Sublime API client (paths from the published OpenAPI spec)
  virustotal.py   VT v3, lookup-only, rate-limited, disk-cached
  headers.py      Deterministic SPF/DKIM/DMARC + spoofing analysis
  iocs.py         Extraction, defanging, quota-aware prioritization
  tools.py        Agent tools + spotlighting
  agent.py        System prompt, Foundry client, run options
  triage.py       Orchestration + escalation
  report.py       HTML for the notebook, Markdown for tickets
infra/            Terraform (AzAPI) + LAB_GUIDE.md
notebooks/        01_triage.ipynb — the analyst interface
tests/            21 tests over the deterministic logic
docs/             This documentation
```

The dependency direction is one-way: `triage.py` → `agent.py` → `tools.py` → clients
(`sublime.py`, `virustotal.py`) and analysis (`headers.py`, `iocs.py`). Nothing below
`tools.py` knows an agent exists, which is why the analysis is testable without a model.

## The design rule worth knowing before you change anything

**Deterministic work stays in Python; the model does judgment.**

Header parsing, IOC extraction, defanging, quota arithmetic and HTML escaping are
computed in Python and handed to the model as established fact. Mechanical checks are
exactly what a model usually gets right and occasionally hallucinates — and a
hallucinated SPF result is worse than no SPF result. The prompt tells the model to treat
those values as fact rather than re-derive them.

The corollary: if you find yourself asking the model to parse, count, or format
something, write a tool instead.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[notebook,msticpy,dev]"
pytest
```

## Tests

```bash
pytest                          # 21 tests
pytest -q tests/test_headers.py
pytest -k defang -v
```

Coverage is deliberately narrow: the parts that must be correct regardless of model
behavior.

| File | Covers |
|---|---|
| `test_headers.py` | SPF/DKIM/DMARC parsing, Received-chain reconstruction, display-name spoofing, punycode and Cyrillic lookalikes |
| `test_iocs.py` | Extraction, defanging, deduplication, quota prioritization |
| `test_report.py` | HTML escaping of attacker-controlled strings, Markdown rendering |

Two constraints on new tests: **no network calls** and **no credentials**. CI installs
only pytest and the small pure-Python deps — deliberately not the Agent Framework — so
the suite cannot start depending on a pre-release package resolving.

`pyproject.toml` sets `pythonpath = ["src"]`, so tests run from a fresh clone without an
editable install.

There is no test for agent behavior, and adding a mocked one would mostly test the mock.
The honest gap is an evaluation against a labelled corpus — see
[What is not proven](#what-is-not-proven).

## Adding a tool

Tools are closures defined inside `build_tools(ctx)` in `tools.py`, so they capture the
per-message `TriageContext` (Sublime client, VirusTotal client, message id, tool log)
without passing it through the model.

```python
def check_something(indicator: str) -> str:
    """One-line summary the model reads to decide whether to call this.

    Explain when to call it and what it returns. This docstring is the tool
    description — it is prompt text, so write it for the model.
    """
    ctx._record("check_something")           # audit trail: shows in result.tool_calls
    try:
        data = ctx.sublime.some_endpoint(indicator)
    except SublimeError as exc:
        return f"Lookup failed: {exc}"       # return the failure, do not raise
    return spotlight(render(data), label="something")   # if any of it is attacker-derived
```

Four rules:

1. **The decorator is `@tool`, not `@ai_function`.** Microsoft Learn still shows the old
   name; it no longer exists in `agent_framework`.
2. **Record the call.** `ctx._record()` feeds `result.tool_calls`, which is the audit
   trail for how a verdict was reached.
3. **Return errors, do not raise them.** A tool that raises aborts the triage; a tool
   that returns "lookup failed" lets the model reason about a partial picture and say so
   in the verdict.
4. **Spotlight anything attacker-derived.** Email content, page titles fetched from a
   link, filenames — anything an attacker chose the text of goes through
   `spotlight()` before it reaches the model.

Add it to the returned list in `build_tools()`. Anything that mutates state belongs
behind a safety switch, following the `_build_action_tool()` pattern: constructed only
when the switch is explicitly true, so the model never sees a tool it must not use.

## Changing the verdict schema

`TriageVerdict` in `models.py` is the contract between the agent and everything
downstream — the notebook, `report.py`, and any ticketing integration. Adding an optional
field is safe. Changing or removing one means updating both renderers in `report.py`.

Structured output is `options={"response_format": TriageVerdict}`, read back from
`response.value`. `ChatOptions` is a `TypedDict`, not a dataclass.

## Terraform

`terraform fmt` and `terraform validate` before committing. `infra/` uses AzAPI for the
Foundry resource, project and model deployments, and AzureRM only for Log Analytics,
Application Insights and RBAC. The reasoning is in
[Deployment](deployment.md#why-azapi-and-not-azurerm).

CI does not currently run Terraform. Adding a `terraform fmt -check` + `validate
-backend=false` job is a welcome PR — it needs no credentials.

## What is not proven

Kept current on purpose. As of the initial public commit:

**Verified** — all modules import; 21 tests pass; `terraform validate` succeeds; the
agent and tools construct with a dummy config; Sublime endpoint paths and parameters come
from the published OpenAPI spec.

**Not verified** — the code has never run against live credentials:

- Every Sublime API **response shape**. Paths are from the spec; the field names read out
  of the message data model, attack score, ASA verdict and hunt results are inferred.
- The Azure Marketplace acceptance flow for Anthropic models.
- `format = "Anthropic"` in the Terraform model-deployment body.
- Whether `effort` passes through correctly via `additional_properties`.
- `terraform apply` has never been run.

If you verify one of these, updating this list is a genuinely valuable PR. If you add
something unverified, add it here.
