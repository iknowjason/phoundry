# Phoundry

*Phishing's `ph`, on Microsoft Foundry.*

A SOC blue-team email triage agent built on **Microsoft Foundry**, using the **Microsoft
Agent Framework**, with **Sublime Security** and **VirusTotal** enrichment. An analyst
triggers it; it does not run on a timer.

[![tests](https://github.com/iknowjason/phoundry/actions/workflows/tests.yml/badge.svg)](https://github.com/iknowjason/phoundry/actions/workflows/tests.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

An analyst opens a Jupyter notebook, pulls the last few minutes of mail, and gets back
evidence-based verdicts: severity, confidence, defanged indicators with rationale and
provenance, authentication analysis, campaign blast radius, and a recommended action.

**→ [Getting started](docs/getting-started.md)** takes you from a clone to a triaged
message in one pass.

```
notebooks/01_triage.ipynb          ← analyst triggers here
        │
        ▼
  TriageSession  ──────────────────────────────────────────────┐
        │                                                       │
        ├── Sublime API      last-5-min messages, MDM, raw EML, │
        │                    attack score, link analysis,       │
        │                    hunt jobs, rule validation         │
        │                                                       │
        └── Agent (MAF)  ──► Claude on Foundry ◄────────────────┘
                  │          (claude-sonnet-5 → claude-opus-5)
                  │
                  └── tools: content · auth forensics · IOC extraction ·
                             VirusTotal · link reputation · campaign hunt ·
                             detection-rule validation
                  │
                  ▼
            TriageVerdict (structured) ──► HTML in notebook + Markdown for tickets
```

---

## The research, in short

Four decisions and why they went the way they did.

### Provisioning: Terraform with the AzAPI provider

Microsoft documents both AzAPI and AzureRM. AzAPI wins on capability — it is the only
one that can create Foundry **connections** and **capability hosts**. More concretely,
there is a documented failure where an `azurerm`-created project returns
`404 ResourceNotFound — The project does not exist` from Agent Framework clients,
because the AI Services connection is never established. Portal-created projects work;
`azurerm`-created ones silently don't.

`infra/` uses AzAPI for the resource, project and deployments, and AzureRM only for
Log Analytics / App Insights / RBAC where it is strictly better. `infra/LAB_GUIDE.md`
is the portal walkthrough — worth reading even if you use Terraform, because it
explains what each resource is for.

### Model: `claude-sonnet-5`, escalating to `claude-opus-5`

Both are GA **hosted on Azure** (in-Azure data path), 1M context, vision, adaptive
thinking. Microsoft's model documentation lists **cybersecurity** among their best-for
workloads. The 1M window matters more than usual here — raw EML plus the Sublime
Message Data Model plus VT reports for every indicator is a large prompt.

Escalation triggers on high severity, low confidence, disagreement with Sublime, or a
detected prompt injection. The second pass is explicitly told not to rubber-stamp the
first.

Alternatives considered: `claude-mythos-5` is a **gated research preview whose access
Anthropic prioritizes for defensive cybersecurity** — a strong fit worth requesting
separately, but not something you can provision today. `claude-fable-5` is
Anthropic-hosted only and carries **0 RPM quota on pay-as-you-go**. GPT-5.x is a
reasonable swap if you want native deployment-time content filters and the GA
Bing-backed web search tool.

### Framework: Microsoft Agent Framework — and MSTICpy is not one

MAF 1.0 shipped **April 2026**, merging Semantic Kernel and AutoGen. Semantic Kernel
v1.x now receives critical fixes only, so it is the wrong choice for new work.

**MSTICpy was a category error in the original brief.** It is Microsoft's Jupyter/Python
threat-intel *analysis* library, not an orchestration framework — there is nothing to
choose between it and MAF. It is used here in its correct role: a tool library called
*inside* the agent for IOC extraction and defanging (`soc_triage/iocs.py`, with a regex
fallback when it isn't installed).

One SDK note the docs get wrong: Claude models on Foundry are served over the
**Anthropic Messages** endpoint (`/anthropic/v1/messages`), not the Responses endpoint,
so they need `AnthropicFoundryClient` from `agent-framework-anthropic` — **not**
`FoundryChatClient`. That package is still pre-release, which is why `pyproject.toml`
pins a beta explicitly. Microsoft Learn's Python example also still shows
`@ai_function`; the decorator is `@tool` in MAF 1.14.

### Ingestion: poll `message-groups/search` over a time window

`GET /v0/message-groups/search` with `created_at[gte]` (inclusive) and `created_at[lt]`
(exclusive) — matching the API's own semantics so a message can't land in two windows.
Group context comes along with each message, which is where the campaign signal lives:
flagged rules, how many mailboxes were hit, and recorded link clicks.

Sublime also supports **webhook Actions** on `message.flagged`, which would be the
better trigger for continuous monitoring. The analysis path is in the package rather
than the notebook precisely so that swap doesn't require a rewrite.

---

## What it does beyond classification

| Capability | Why it earns its place |
|---|---|
| **Deterministic header forensics** | SPF/DKIM/DMARC, Received-chain reconstruction, display-name spoofing, punycode and Cyrillic-lookalike detection — computed in Python (`headers.py`), handed to the model as fact. Mechanical checks are exactly what a model *usually* gets right and occasionally hallucinates. |
| **Quota-aware enrichment** | Public VirusTotal is 4 req/min, 500/day. `iocs.prioritize()` ranks hashes first, then shortened links, then everything else, and the agent is instructed to spend the budget on indicators that change its verdict. |
| **Campaign scoping** | Launches a Sublime MQL hunt for the same indicator and reports blast radius. Mailboxes with recorded link clicks are surfaced as a confirmed incident, not a triage item. |
| **Disagreement flagging** | Compares itself to Sublime's own attack score and flags material differences. A second opinion that always agrees is worthless; the disagreements are where a human should look first. |
| **Auto-proposed detection rule** | Drafts a Sublime MQL rule for the campaign and validates it via `POST /v0/rules/validate` before it appears in the report. Never auto-deployed. |
| **Injection defense, both layers** | Email content is wrapped in provenance markers (`spotlight()`) and the model is told to report manipulation attempts rather than obey them; Prompt Shields with Spotlighting covers the deployment layer. Detected injections become a malicious indicator in their own right. |
| **Structured output** | The agent is constrained to a Pydantic schema, so nothing downstream parses prose. |

---

## Setup

The short version. [docs/getting-started.md](docs/getting-started.md) is the long version,
with prerequisites and the checks that tell you whether each step actually worked.

```bash
git clone https://github.com/iknowjason/phoundry.git && cd phoundry
python -m venv .venv && source .venv/bin/activate
pip install -e ".[notebook,msticpy]"
cp .env.example .env          # fill in
```

**Infrastructure** — either:

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # fill in subscription_id
terraform init && terraform apply
terraform output env_file_snippet              # paste into .env
```

or follow [`infra/LAB_GUIDE.md`](infra/LAB_GUIDE.md) in the portal.

**Then:**

```bash
az login                       # the agent authenticates as you
jupyter lab notebooks/01_triage.ipynb
```

A cell-by-cell walkthrough — including what to look at first in a verdict — is in
[docs/running-triage.md](docs/running-triage.md).

---

## Safety posture

Two switches in `.env`, both **default closed**:

```bash
ALLOW_MAILBOX_ACTIONS=false   # agent cannot trash/quarantine anything
ALLOW_VT_SUBMIT=false         # never implemented — see below
```

- **Read-only by default.** The mailbox action tool is not even registered with the
  agent unless `ALLOW_MAILBOX_ACTIONS=true`. Section 5 of the notebook prints the
  recommended action and the exact call; you run it. There is deliberately no
  "apply all".
- **Lookup-only VirusTotal.** Submission endpoints are not implemented at all.
  Uploading a customer's attachment to VT publishes it to every VT enterprise
  subscriber — lookup by hash is safe, submission is a data-leak path.
- **Authenticated as a person.** No shared service principal. Sublime's access
  justification and Foundry's audit log both name the analyst who ran the notebook.
- **Untrusted content is marked as such.** Every piece of email content reaching the
  model is wrapped in `<<<UNTRUSTED_EMAIL_CONTENT>>>` markers with an explicit notice
  that it is evidence, not instruction.
- **Notebook outputs are sensitive.** A saved `.ipynb` embeds message bodies,
  recipient addresses and IOCs. `.gitignore` covers `reports/` and `.env`; clear
  notebook outputs before sharing.

---

## Layout

```
src/soc_triage/
  config.py       settings + safety switches (default closed)
  models.py       TriageVerdict — the structured output contract
  sublime.py      Sublime API client (paths taken from the OpenAPI spec)
  virustotal.py   VT v3, lookup-only, rate-limited, disk-cached
  headers.py      deterministic auth + spoofing analysis
  iocs.py         extraction, defanging, quota-aware prioritization
  tools.py        agent tools + spotlighting
  agent.py        system prompt, Foundry client, run options
  triage.py       orchestration + escalation
  report.py       HTML for the notebook, Markdown for tickets
infra/            Terraform (AzAPI) + LAB_GUIDE.md
notebooks/        01_triage.ipynb
tests/            21 tests over the deterministic logic
```

```bash
pytest        # 21 passing
```

Tests cover the parts that must be right regardless of model behavior: header
forensics, IOC handling, quota prioritization, and HTML escaping of attacker-controlled
strings in reports.

---

## Documentation

| Document | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Prerequisites, install, deploy, configure, first run |
| [Deployment](docs/deployment.md) | Provisioning Foundry with Terraform, content filtering, cost, teardown |
| [Configuration](docs/configuration.md) | Every environment variable and Terraform variable |
| [Running a triage](docs/running-triage.md) | The notebook cell by cell, and using the library without it |
| [Troubleshooting](docs/troubleshooting.md) | Errors you are likely to hit, and what they actually mean |
| [Development](docs/development.md) | Layout, tests, adding a tool, how the pieces fit |
| [Lab guide](infra/LAB_GUIDE.md) | Provisioning Foundry by hand in the portal, with each resource explained |

---

## Known limits

- **Not continuous monitoring.** This is an on-demand analyst tool. The original brief
  asked for a 5-minute polling trigger; that path is a small wrapper around
  `TriageSession.triage_many()` plus a cursor store, and the Sublime webhook is the
  better trigger for it.
- **`agent-framework-anthropic` is pre-release.** No stable build exists yet; the
  pinned beta may move.
- **Hunt jobs are polled for 30 seconds.** Longer hunts return "scoping pending"
  rather than blocking triage.
- **Proposed detection rules are drafts.** They are validated for syntax, not for
  false-positive rate. A human detection engineer reviews before anything ships.
- **The agent has not been evaluated against a labelled corpus.** Foundry supports
  evaluations and tracing; wiring a golden set is the obvious next step and the honest
  prerequisite to any claim about accuracy.

---

## Project status

This is a **demo and reference implementation**, not a supported product. It is complete
and tested, and it has never run against a live tenant. Those are two different claims and
this section keeps them apart.

**Verified** — all modules import; 21 tests pass over the deterministic logic;
`terraform validate` succeeds; the agent and its tools construct with a dummy
configuration; Sublime endpoint paths and parameters are taken from the published OpenAPI
spec.

**Not verified** — no credentials have ever been configured:

- Every Sublime API **response shape**. The paths are from the spec; the field names read
  out of the message data model, attack score, ASA verdict and hunt results are inferred.
- The Azure Marketplace acceptance flow for Anthropic models.
- The `format = "Anthropic"` value in the Terraform model-deployment body.
- Whether `effort` passes through correctly via `additional_properties`.
- `terraform apply` has never been run.

If you run this against a real tenant, the most valuable thing you can contribute back is
striking an item off that second list — or adding one.

---

## Contributing

Issues and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the setup
and the few rules specific to this project — deterministic logic stays deterministic,
safety switches default closed, and no real mail in the repository, ever.

Security issues go through [private vulnerability reporting](SECURITY.md), not the issue
tracker.

## License

[Apache License 2.0](LICENSE) © 2026 Jason Ostrom.

---

## Sources

- [Use Terraform to create Microsoft Foundry](https://learn.microsoft.com/en-us/azure/foundry/how-to/create-resource-terraform)
- [AI Foundry project created via Terraform is not usable from Agent Framework](https://learn.microsoft.com/en-us/answers/questions/5607343/ai-foundry-project-created-via-terraform-is-not-us)
- [Claude models in Microsoft Foundry](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/claude-models)
- [What is Microsoft Foundry Agent Service?](https://learn.microsoft.com/en-us/azure/foundry/agents/overview)
- [Microsoft Foundry model provider (Agent Framework)](https://learn.microsoft.com/en-us/agent-framework/agents/providers/microsoft-foundry)
- [Migrate Semantic Kernel and AutoGen to Microsoft Agent Framework](https://devblogs.microsoft.com/agent-framework/migrate-your-semantic-kernel-and-autogen-projects-to-microsoft-agent-framework-release-candidate/)
- [Sublime Security API reference](https://docs.sublime.security/reference/introduction) · [OpenAPI spec](https://docs.sublime.security/openapi/sublime-platform-api.json)
- [Sublime webhook actions](https://docs.sublime.security/docs/webhooks)
- [VirusTotal API v3 overview](https://docs.virustotal.com/reference/overview) · [Public vs Premium quotas](https://docs.virustotal.com/reference/public-vs-premium-api)
- [Prompt Shields in Microsoft Foundry](https://learn.microsoft.com/en-us/azure/foundry/openai/concepts/content-filter-prompt-shields) · [Spotlighting announcement](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/better-detecting-cross-prompt-injection-attacks-introducing-spotlighting-in-azur/4458404)
- [MSTICpy](https://github.com/microsoft/msticpy)
