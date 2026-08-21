# Deployment

Provisioning the Azure side. If you would rather click through the portal and have each
resource explained as you go, use [`../infra/LAB_GUIDE.md`](../infra/LAB_GUIDE.md)
instead — it produces the same result.

> **Status.** The Terraform in `infra/` validates, and the resource bodies follow the
> documented API shapes. It has **not** been applied against a live subscription by the
> author. Treat your first `apply` as the verification pass, and please open an issue
> with what you hit.

---

## What gets created

| Resource | Provider | Why |
|---|---|---|
| Resource group | AzAPI | Container. Created if absent. |
| Foundry account (`Microsoft.CognitiveServices/accounts`) | AzAPI | `kind = AIServices`, `allowProjectManagement = true`. This is what makes it a Foundry resource rather than a plain Cognitive Services account. |
| Foundry project | AzAPI | The scope agents run in. |
| `claude-sonnet-5` deployment | AzAPI | Primary triage model, GlobalStandard SKU. |
| `claude-opus-5` deployment | AzAPI | Escalation reviewer. Chained after the first — deployments on one account serialize server-side, and creating them in parallel throws a spurious conflict. |
| Log Analytics workspace + Application Insights | AzureRM | Agent tracing. Optional (`enable_app_insights`). |
| `Azure AI User` role assignments | AzureRM | One per entry in `analyst_principal_ids`. |

Resource names get a five-character random suffix, because `customSubDomainName` must be
globally unique.

### Why AzAPI and not AzureRM

AzAPI is the only one of the two that can create Foundry **connections** and **capability
hosts**. More concretely, there is a documented failure mode where an `azurerm`-created
project returns `404 ResourceNotFound — The project does not exist` from Agent Framework
clients, because the AI Services connection is never established. Portal-created and
AzAPI-created projects work; `azurerm`-created ones silently do not.

AzureRM is used only for Log Analytics, Application Insights and RBAC, where it is
strictly the better provider.

### Two settings that are not optional

- **`customSubDomainName`** — without it there is no `https://<name>.services.ai.azure.com`
  endpoint at all, and every stateful Foundry feature fails, including the Anthropic
  Messages endpoint this project depends on.
- **`allowProjectManagement = true`** — without it you get a Cognitive Services account
  that cannot host projects.

---

## Prerequisites

```bash
terraform version        # >= 1.9
az account show          # signed in, correct subscription
az account show --query id -o tsv               # → subscription_id
az ad signed-in-user show --query id -o tsv     # → analyst_principal_ids
```

You need rights to create resource groups and to assign roles. Role assignment usually
requires Owner or User Access Administrator; if you only have Contributor, leave
`analyst_principal_ids` empty and have someone grant **Azure AI User** on the Foundry
resource separately.

## Accept the Anthropic Marketplace offer first

Claude models on Foundry are sold through an Azure Marketplace offer and bill in **Claude
Consumption Units (CCU)**. Until the offer is accepted on the subscription, creating a
Claude deployment fails.

If it has not been accepted, do the two-pass apply:

```bash
# Pass 1 — everything except the model deployments
terraform apply -var 'deploy_claude_models=false'

# Accept the offer: Foundry portal → Model catalog → Claude → Deploy → accept terms

# Pass 2 — add the deployments
terraform apply -var 'deploy_claude_models=true'
```

Setting it in `terraform.tfvars` works the same way and is easier to remember what you
did.

## Apply

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars

terraform init
terraform plan       # read it; role assignments and model deployments are the risky bits
terraform apply
```

Then wire the outputs into the application config:

```bash
terraform -chdir=infra output -raw env_file_snippet   # paste into ../.env
```

Every variable and output is listed in [Configuration](configuration.md#infrastructure-settings-infraterraformtfvars).

---

## Content filtering

**Claude deployments on Foundry have no content filter by default**, unlike Azure OpenAI
model deployments. This matters more here than in most applications: the agent reads
attacker-authored email and has tools it can call.

The in-code defenses are real but partial — email content is wrapped in
`<<<UNTRUSTED_EMAIL_CONTENT>>>` provenance markers by `tools.spotlight()`, the system
prompt instructs the model to report manipulation attempts rather than obey them, and a
detected injection becomes a malicious indicator in its own right. That is defense in
depth, not a guarantee.

Add the deployment-layer control:

1. Foundry portal → **Guardrails + controls** → **Content filters** → create a filter.
2. Enable **Prompt Shields for indirect attacks** — this is the one that matters for
   email. Spotlighting complements the in-code markers.
3. Apply the filter to both the triage and escalation deployments.

`infra/LAB_GUIDE.md` step 6 walks the same thing with screenshots-worth of detail.

## Cost

The floor is near zero — Foundry accounts and projects cost nothing at rest, and
GlobalStandard deployments bill per token, not per hour. Real cost comes from triage
volume: each message makes several tool-augmented calls, and raw EML plus the Sublime
message data model plus VirusTotal reports is a large prompt. Escalation runs a second
pass on Opus.

Log Analytics has a small ingestion cost. Set `enable_app_insights = false` if you do not
want tracing.

Watch the pay-as-you-go quota rather than the bill at first: **40 RPM / 40K ITPM** for
Claude on Foundry. That is why the notebook triages with `concurrency=3`.

## Teardown

```bash
terraform -chdir=infra destroy
```

Destroy does not remove the Marketplace offer acceptance — that stays on the
subscription, which is convenient if you redeploy. `infra/LAB_GUIDE.md` has the portal
teardown for a hand-built environment.

Cognitive Services accounts soft-delete. If you redeploy into the same resource group
with the same name and get a conflict, purge it:

```bash
az cognitiveservices account list-deleted -o table
az cognitiveservices account purge \
  --name <name> --resource-group <rg> --location <region>
```

The random name suffix normally makes this a non-issue.
