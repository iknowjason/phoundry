# Getting started

From a clone to a triaged message. Budget about 45 minutes the first time, most of it
waiting on Azure.

If you only want to run the tests and read the code, you can stop after
[step 2](#2-install) — the deterministic test suite needs no credentials and no cloud
resources at all.

---

## What you need first

| | Why | Check it |
|---|---|---|
| **Python 3.11+** | The package targets 3.11–3.13. | `python3 --version` |
| **An Azure subscription** | Foundry resource and Claude model deployments. You need rights to create resource groups and assign roles. | `az account show` |
| **Azure CLI** | The agent authenticates as the signed-in analyst. | `az version` |
| **Terraform 1.9+** | Only if you provision with Terraform rather than the portal. | `terraform version` |
| **A Sublime Security tenant + API key** | This is the mail source. There is no offline mode. | Dashboard → Settings → API keys |
| **A VirusTotal API key** | Optional but recommended. The free public tier works. | [virustotal.com](https://www.virustotal.com) → your profile |

> **Sublime is a hard dependency.** Every message this agent triages comes from the
> Sublime API — the message data model, the raw EML, the attack score, the hunt results.
> Without a tenant there is nothing to triage. A Sublime free/community tenant with a
> few forwarded phishing samples is enough to exercise the whole path.

---

## 1. Clone

```bash
git clone https://github.com/iknowjason/foundragent.git
cd foundragent
```

## 2. Install

```bash
python3 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e ".[notebook,msticpy,dev]"
```

The extras are worth understanding:

- `notebook` — JupyterLab, ipywidgets and pandas. Needed to run the analyst notebook.
- `msticpy` — Microsoft's threat-intel analysis library, used for IOC extraction and
  defanging. **Optional**: `iocs.py` falls back to regex extraction when it is absent.
- `dev` — pytest and pytest-asyncio.

Confirm the install:

```bash
pytest
# 21 passed
```

Those 21 tests cover header forensics, IOC handling, quota prioritization and HTML
escaping — everything that must be correct regardless of what the model does. They make
no network calls, so a green suite here proves the install and nothing about your
credentials.

> **Note on `agent-framework-anthropic`.** There is no stable release of this package —
> betas only. `pyproject.toml` names a specific beta on purpose; a `>=1.0.0` specifier
> makes pip refuse to resolve it. If the pin goes stale, see
> [Troubleshooting](troubleshooting.md#pip-cannot-resolve-agent-framework-anthropic).

## 3. Provision Microsoft Foundry

Two paths. They produce the same thing.

**Terraform** (recommended — reproducible, and tears down cleanly):

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
# fill in subscription_id, and your object id in analyst_principal_ids:
#   az account show --query id -o tsv
#   az ad signed-in-user show --query id -o tsv

terraform init
terraform apply
```

**The portal**, walked through step by step with an explanation of what each resource is
for: [`../infra/LAB_GUIDE.md`](../infra/LAB_GUIDE.md).

Either way, two things trip people up:

1. **The Anthropic Marketplace offer must be accepted on the subscription** before a
   Claude deployment will succeed. If it has not been, set `deploy_claude_models = false`
   for the first apply, accept the offer in the Foundry portal, then re-apply with it
   back to `true`.
2. **Claude deployments on Foundry have no content filter by default**, unlike Azure
   OpenAI models. You are feeding attacker-authored email to a tool-calling agent — turn
   on Prompt Shields. See [Deployment → content filtering](deployment.md#content-filtering).

Details, cost notes and teardown: [Deployment](deployment.md).

## 4. Configure

```bash
cd ..
cp .env.example .env
```

If you used Terraform, most of it is generated for you:

```bash
terraform -chdir=infra output -raw env_file_snippet
```

Paste that into `.env`, then add your Sublime and VirusTotal keys. The minimum required
to start is:

```bash
ANTHROPIC_FOUNDRY_RESOURCE=soctriage1a2b   # the resource NAME, not a URL
SUBLIME_API_KEY=...
```

Leave `ANTHROPIC_FOUNDRY_API_KEY` **blank**. Blank means the agent authenticates with
your Entra identity via `az login`, so Foundry's audit log names the human who ran the
triage rather than a shared service principal. Every variable is documented in
[Configuration](configuration.md).

Both safety switches default closed and should stay that way for your first run:

```bash
ALLOW_MAILBOX_ACTIONS=false   # the agent cannot quarantine or trash anything
ALLOW_VT_SUBMIT=false         # never implemented; submission is a data-leak path
```

## 5. Sign in and run

```bash
az login
jupyter lab notebooks/01_triage.ipynb
```

Run the cells in order:

1. **Connect** — prints a redacted settings table. If it renders, your config parsed and
   your keys are present. It does not prove they are *valid*.
2. **Pull recent messages** — the last 5 minutes of inbound mail. In a quiet test tenant
   this is usually empty; widen `LOOKBACK_MINUTES` to `1440` and re-run.
3. **Triage** — the agent runs. Expect roughly 30–90 seconds per message; each one makes
   several tool-augmented model calls.
4. **Read the reports** — severity, confidence, defanged indicators with provenance,
   authentication analysis, campaign blast radius, recommended action.

A cell-by-cell walkthrough, including what to look at first in a verdict, is in
[Running a triage](running-triage.md).

---

## Verifying it actually works

The install is proven by `pytest`. The *deployment* is proven by getting a verdict back.
In between, these are the useful checkpoints:

```bash
# Azure identity and subscription
az account show --query "{sub:name, user:user.name}" -o table

# Foundry resource exists and has the required custom subdomain
az cognitiveservices account show \
  --name "$ANTHROPIC_FOUNDRY_RESOURCE" \
  --resource-group rg-soc-triage-agent \
  --query "properties.endpoint" -o tsv

# Sublime key is valid (should return JSON, not 401)
curl -s -H "Authorization: Bearer $SUBLIME_API_KEY" \
  "$SUBLIME_BASE_URL/v0/message-groups/search?limit=1" | head -c 300
```

If any of those fail, [Troubleshooting](troubleshooting.md) covers the common causes.

---

## Where to go next

- [Running a triage](running-triage.md) — the notebook in detail, and calling
  `TriageSession` from your own code
- [Configuration](configuration.md) — full variable reference
- [Development](development.md) — how the pieces fit, and how to add a tool
