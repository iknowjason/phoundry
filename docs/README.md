# Documentation

User documentation for **Phoundry**, a SOC blue-team email triage agent on Microsoft
Foundry. Start at
**[Getting started](getting-started.md)** — it takes you from a clone to a triaged
message in one pass.

| Document | What it covers |
|---|---|
| [Getting started](getting-started.md) | Prerequisites, install, deploy, configure, first run |
| [Deployment](deployment.md) | Provisioning Foundry with Terraform, content filtering, cost, teardown |
| [Configuration](configuration.md) | Every environment variable and Terraform variable |
| [Running a triage](running-triage.md) | The notebook cell by cell, and using the library without it |
| [Troubleshooting](troubleshooting.md) | Errors you are likely to hit, and what they actually mean |
| [Development](development.md) | Layout, tests, adding a tool, how the pieces fit |

Provisioning Foundry by hand in the portal — with an explanation of what each resource
is for — is in [`../infra/LAB_GUIDE.md`](../infra/LAB_GUIDE.md). It is worth reading even
if you use Terraform.

Design rationale — why AzAPI, why these models, why Microsoft Agent Framework, why
MSTICpy is not an orchestration framework — is in the
[project README](../README.md#the-research-in-short).
