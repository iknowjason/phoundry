# Configuration

Two files configure this project. `.env` configures the **application**;
`infra/terraform.tfvars` configures the **infrastructure**. Neither is committed —
`.gitignore` covers `.env` and `*.tfvars`, with the `.example` files tracked as
templates.

```bash
cp .env.example .env
cp infra/terraform.tfvars.example infra/terraform.tfvars
```

Settings are loaded by `soc_triage.config.load_settings()`, which reads `.env` from the
repository root. It raises `ConfigError` listing everything missing rather than failing
later on a confusing HTTP error.

---

## Application settings (`.env`)

### Microsoft Foundry

| Variable | Required | Default | Notes |
|---|---|---|---|
| `ANTHROPIC_FOUNDRY_RESOURCE` | **yes** | — | The Foundry resource **name**, not a URL. The Anthropic endpoint is derived as `https://<resource>.services.ai.azure.com/anthropic/v1/messages`. |
| `ANTHROPIC_FOUNDRY_API_KEY` | no | *(blank)* | **Leave blank.** Blank selects Entra ID auth via `az login`, so the audit log names the analyst. Set it only for an unattended context where no human identity exists. |
| `FOUNDRY_PROJECT_ENDPOINT` | no | — | The Foundry *project* endpoint. Used for tracing and by GPT-family models; not needed for Claude triage. |
| `TRIAGE_MODEL` | no | `claude-sonnet-5` | Must match the **deployment name** in Foundry, which is not necessarily the model name. |
| `ESCALATION_MODEL` | no | `claude-opus-5` | Second-pass model for high-severity or low-confidence verdicts. |

`Settings.use_entra_auth` is simply "no API key was set". There is no third mode.

### Sublime Security

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SUBLIME_API_KEY` | **yes** | — | Bearer token. Needs read access to messages; only needs action scope if you enable mailbox actions. |
| `SUBLIME_BASE_URL` | no | `https://platform.sublime.security` | **Region-specific.** Using the wrong region returns 401/404 with a valid key. |

Regional base URLs:

```
https://platform.sublime.security          NA-East (default)
https://na-west.platform.sublime.security  NA-West
https://ca.platform.sublime.security       Canada
https://uk.platform.sublime.security       United Kingdom
https://eu.platform.sublime.security       Europe
https://au.platform.sublime.security       Australia
```

### VirusTotal

| Variable | Required | Default | Notes |
|---|---|---|---|
| `VT_API_KEY` | no | — | Without it, VirusTotal enrichment raises `ConfigError` when the agent reaches for it; the rest of triage still works. |
| `VT_TIER` | no | `public` | `public` throttles client-side to 4 requests/minute (500/day). `premium` removes the client-side throttle. |

The public quota is small enough that it shapes the design: `iocs.prioritize()` ranks
hashes first, then shortened links, then everything else, and the agent is told to spend
its budget on indicators that could change the verdict. Lookups are cached to disk in
`.cache/`.

### Safety switches

| Variable | Default | Effect |
|---|---|---|
| `ALLOW_MAILBOX_ACTIONS` | `false` | When false, the `action_message` tool is **not registered with the agent at all** — it cannot quarantine, trash or restore anything. The notebook prints the recommended action and the exact call for you to run. There is deliberately no "apply all". |
| `ALLOW_VT_SUBMIT` | `false` | Reserved. VirusTotal *submission* is not implemented in any code path. Uploading a customer's attachment to VT publishes it to every VT enterprise subscriber; lookup by hash is safe, submission is a data-leak path. |

Truthy values are `1`, `true`, `yes`, `on` (case-insensitive). Anything else is false,
including an empty value — the switches fail closed.

### Paths

Not environment variables, but worth knowing. Both are created on load and both are
gitignored:

- `.cache/` — VirusTotal lookup cache.
- `reports/` — Markdown reports written by `save_report()`. **Contains real message
  content.**

---

## Infrastructure settings (`infra/terraform.tfvars`)

| Variable | Default | Notes |
|---|---|---|
| `subscription_id` | *(required)* | `az account show --query id -o tsv` |
| `location` | `eastus2` | Claude models deploy as Global Standard. `eastus2` and `swedencentral` are reliable; check availability before changing. |
| `resource_group_name` | `rg-soc-triage-agent` | Created if absent. |
| `project_name` | `soctriage` | 3–12 lowercase alphanumerics; used to derive resource names, with a random suffix appended for global uniqueness. |
| `triage_model` | `claude-sonnet-5` | Requires the Anthropic Marketplace offer on the subscription. Bills through Claude Consumption Units (CCU). |
| `triage_model_capacity` | `1` | Capacity units for the triage deployment. |
| `escalation_model` | `claude-opus-5` | Second-pass reviewer. |
| `escalation_model_capacity` | `1` | |
| `deploy_claude_models` | `true` | **Set `false` for the first apply** if the Marketplace offer has not been accepted yet — the deployment fails until it is. Accept in the portal, then re-apply with `true`. |
| `enable_app_insights` | `true` | Application Insights + Log Analytics for agent tracing. |
| `analyst_principal_ids` | `[]` | Entra object IDs granted **Azure AI User** on the Foundry resource. `az ad signed-in-user show --query id -o tsv`. Leaving this empty means nobody can run the notebook. |
| `tags` | workload/environment/managed_by | Applied to all resources. |

### Wiring the outputs into `.env`

```bash
terraform -chdir=infra output -raw env_file_snippet
```

produces the Foundry half of `.env`:

```
ANTHROPIC_FOUNDRY_RESOURCE=...
FOUNDRY_PROJECT_ENDPOINT=...
TRIAGE_MODEL=...
ESCALATION_MODEL=...
```

Other outputs: `foundry_resource_name`, `foundry_endpoint`, `anthropic_endpoint`,
`project_name`, `project_endpoint`, `triage_model`, `escalation_model`, and
`app_insights_connection_string` (marked sensitive).

---

## Checking what loaded

`Settings.describe()` returns a redacted summary — secrets show as their last four
characters. The notebook's first cell renders it as a table. In a shell:

```python
from soc_triage.config import load_settings
for k, v in load_settings().describe().items():
    print(f"{k:22} {v}")
```

```
Foundry resource       soctriage1a2b
Triage model           claude-sonnet-5
Escalation model       claude-opus-5
Foundry auth           Entra ID (az login)
Sublime endpoint       https://platform.sublime.security
Sublime key            …a91f
VirusTotal             public (…3c02)
Mailbox actions        disabled (read-only)
VT submission          disabled (lookup only)
```

This proves your configuration *parsed*. It does not prove any credential is valid —
that takes a live call.
