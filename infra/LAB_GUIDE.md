# Lab Guide — Provisioning Microsoft Foundry by hand

The Terraform in this directory is the recommended path. This guide is here for two
reasons: it is the fastest way to *understand* what the Terraform builds, and it is
the reliable fallback when a preview API shifts under the provider.

Roughly 20 minutes. You need an Azure subscription and permission to create
Cognitive Services resources and accept Marketplace offers.

---

## Why not just clickops everything?

Worth knowing before you choose:

| | Terraform (AzAPI) | Azure CLI | Portal |
|---|---|---|---|
| Repeatable / reviewable | ✅ | partial | ❌ |
| Tear down cleanly | ✅ `destroy` | manual | manual |
| Foundry connections + capability hosts | ✅ | partial | ✅ |
| Survives preview API churn | ⚠️ | ⚠️ | ✅ |
| Teaches you the resource model | ❌ | partial | ✅ |

One thing that is **not** a matter of taste: **do not create the Foundry project with
the `azurerm` provider.** `azurerm_cognitive_account_project` does not establish the
AI Services connection that Agent Framework clients expect, and agent creation then
fails with `404 ResourceNotFound — The project does not exist`. Use AzAPI or the
portal. The Terraform here uses AzAPI for exactly this reason.

---

## Step 1 — Create the Foundry resource

1. Go to the [Azure portal](https://portal.azure.com) → **Create a resource**.
2. Search for **Azure AI Foundry** (may appear as *Microsoft Foundry*) → **Create**.
3. Fill in:
   - **Subscription / Resource group** — create `rg-soc-triage-agent`.
   - **Name** — must be globally unique, e.g. `soctriage<yourinitials>`.
   - **Region** — `East US 2` or `Sweden Central`. Claude models deploy as Global
     Standard, but the resource still needs a home region.
   - **Pricing tier** — `S0`.
4. On **Identity**, enable **System assigned managed identity**.
5. Review + create.

> **What this creates:** a `Microsoft.CognitiveServices/accounts` resource with
> `kind=AIServices` and `allowProjectManagement=true`. The portal sets the custom
> subdomain for you — this is what makes `https://<name>.services.ai.azure.com`
> resolve. Without it, every stateful Foundry feature fails.

**Verify:** on the resource **Overview**, the endpoint reads
`https://<name>.services.ai.azure.com/`. If it shows a regional
`*.api.cognitive.microsoft.com` URL instead, the custom subdomain is missing and you
need to recreate the resource.

---

## Step 2 — Create the project

1. Open [ai.azure.com](https://ai.azure.com) and sign in.
2. Select your Foundry resource → **New project**.
3. Name it `soctriage-triage`. Create.

Projects are folders for stateful work — agents, threads, evaluations, connections.
The notebook only needs the resource for inference, but the project is where tracing
and evaluation land.

---

## Step 3 — Accept the Anthropic Marketplace offer

Claude models are **Non-Microsoft Products** sold through Azure Marketplace and billed
in **Claude Consumption Units (CCU)**, separate from Azure OpenAI pricing. First
deployment triggers a subscription flow.

1. In the Foundry portal → **Model catalog**.
2. Search `claude-sonnet-5` → **Deploy**.
3. Accept the Marketplace terms when prompted.

> **If the offer is blocked:** your account may lack Marketplace purchase rights, which
> is common on enterprise subscriptions. This is an Azure permissions issue, not a
> Foundry one — ask whoever owns Marketplace acquisitions in your tenant. You can
> keep building in the meantime by setting `TRIAGE_MODEL` to a GPT-family deployment.

---

## Step 4 — Deploy the models

Deploy two:

| Deployment name | Role | Why |
|---|---|---|
| `claude-sonnet-5` | Primary triage | GA hosted on Azure, 1M context, vision, adaptive thinking. Microsoft lists cybersecurity among its best-for workloads. |
| `claude-opus-5` | Escalation | Same family, higher ceiling, supports `max` effort. Used only for the second pass. |

For each: **Model catalog** → select model → **Deploy** → **Global Standard** →
keep the deployment name identical to the model name (the code assumes this) → Deploy.

> **Capacity:** start at 1. Pay-as-you-go caps you at 40 RPM / 40K input tokens per
> minute regardless, and the notebook runs 3 triages concurrently at most.

**Verify:** **Deployments** lists both as *Succeeded*.

---

## Step 5 — Grant yourself access

The notebook authenticates as the signed-in user rather than with an API key, so the
Foundry audit trail names a person.

1. Foundry resource in the Azure portal → **Access control (IAM)**.
2. **Add** → **Add role assignment**.
3. Role: **Azure AI User** (recently renamed **Foundry User**; the role ID is unchanged,
   and you may see either name during the rollout).
4. Assign to your own user. Save.

```bash
# Your object id, if you need it:
az ad signed-in-user show --query id -o tsv
```

---

## Step 6 — Turn on content filtering

**Do not skip this one.** Claude deployments on Foundry ship with **no content filtering
at deployment time** — unlike Azure OpenAI models, which get a default filter. This
application feeds attacker-authored email directly into a tool-calling agent, which is
the textbook cross-prompt-injection (XPIA) setup.

1. Foundry portal → **Guardrails + controls** (older builds: *Content filters*).
2. **Create content filter**.
3. Under input filters, enable **Prompt Shields for indirect attacks**, and turn on
   **Spotlighting** — it tags untrusted input with provenance markers so the model can
   distinguish data from instructions.
4. Apply the filter to both deployments.

The application does the prompt-level half of this too (`soc_triage.tools.spotlight`
wraps all email content in untrusted-content markers, and the system prompt instructs
the model to report injection attempts rather than obey them). Neither layer is
sufficient alone.

---

## Step 7 — Configure the app

```bash
cp .env.example .env
```

Set:

```bash
ANTHROPIC_FOUNDRY_RESOURCE=soctriage<yourinitials>   # resource NAME, not the URL
FOUNDRY_PROJECT_ENDPOINT=https://soctriage<yourinitials>.services.ai.azure.com
TRIAGE_MODEL=claude-sonnet-5
ESCALATION_MODEL=claude-opus-5
# leave ANTHROPIC_FOUNDRY_API_KEY blank to authenticate as yourself
```

Then sign in and smoke-test:

```bash
az login
python -c "
import asyncio
from soc_triage.config import load_settings
from soc_triage.agent import build_client
from agent_framework import Agent

async def main():
    s = load_settings()
    agent = Agent(client=build_client(s, s.triage_model), instructions='Reply with OK.')
    print((await agent.run('ping')).text)

asyncio.run(main())
"
```

`OK` means Foundry, auth, and the deployment are all working.

---

## Step 8 — API keys for Sublime and VirusTotal

**Sublime:** dashboard → **Automate → API** → **New Key**. Note your regional base URL —
`platform.sublime.security` (NA-East) is the default, but there are separate
`na-west`, `ca`, `uk`, `eu` and `au` hosts and a key only works against its own region.

**VirusTotal:** profile → **API Key**. A public key allows **4 requests/minute and
500/day** — the client throttles and caches to stay inside that, and the agent is
instructed to spend the budget on indicators that change its verdict rather than
enumerate everything.

---

## Tearing down

Portal-created resources: delete the resource group.

Terraform:

```bash
cd infra
terraform plan -destroy -out main.destroy.tfplan
terraform apply main.destroy.tfplan
```

Model deployments are billed on consumption, but an idle Foundry resource still
accrues nothing meaningful — the cost here is per-token, so the main reason to tear
down is hygiene rather than spend.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `404 ResourceNotFound — The project does not exist` | Project created with `azurerm`. Recreate with AzAPI or the portal. |
| `DeploymentNotFound` | Deployment name differs from the model name. The code uses the deployment name from `.env`. |
| `401` / `AuthenticationFailed` | Not signed in (`az login`), or missing the **Azure AI User** role. |
| Endpoint is `*.api.cognitive.microsoft.com` | Custom subdomain missing — recreate the Foundry resource. |
| `429` from Foundry | Pay-as-you-go is 40 RPM / 40K ITPM. Lower `concurrency` in the notebook. |
| Marketplace terms won't accept | Subscription lacks Marketplace purchase rights. Not fixable from Foundry. |
| Sublime `401` | Key belongs to a different region than `SUBLIME_BASE_URL`. |
