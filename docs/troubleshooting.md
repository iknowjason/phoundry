# Troubleshooting

Ordered roughly by when you hit them.

---

## Install

### `pip cannot resolve agent-framework-anthropic`

```
ERROR: Could not find a version that satisfies the requirement agent-framework-anthropic>=1.0.0
```

There is **no stable release** of this package — betas only. A `>=1.0.0` specifier makes
pip refuse to resolve it, because pip will not select a pre-release for a specifier that
does not mention one. `pyproject.toml` names a specific beta on purpose.

If the pinned beta has been yanked, find a current one and update the pin:

```bash
pip index versions agent-framework-anthropic --pre
```

### `ModuleNotFoundError: No module named 'soc_triage'`

The editable install is missing or its path file is stale. Reinstall:

```bash
pip install -e ".[notebook,msticpy,dev]"
```

`pytest` itself is insulated from this — `pyproject.toml` sets `pythonpath = ["src"]`, so
the suite runs from a fresh clone with nothing installed but pytest. If `pytest` works
and your own script does not, that is the editable install, not your code.

### `AttributeError: module 'agent_framework' has no attribute 'ai_function'`

The Microsoft Agent Framework tool decorator is **`@tool`**, not `@ai_function`.
Microsoft Learn's Python page still shows `@ai_function`; it no longer exists in
`agent_framework`. Verified against MAF 1.14.

---

## Azure and Foundry

### `404 ResourceNotFound — The project does not exist`

The single most common Foundry-with-Terraform failure, and it is not about your code.

A Foundry project created with the **`azurerm`** provider is broken for agents: the AI
Services connection is never established, so Agent Framework clients cannot see the
project even though it is visible in the portal. Projects created with **AzAPI** or in
the portal work.

`infra/` uses AzAPI for exactly this reason. If you provisioned by hand with `azurerm`,
recreate the project.

### Nothing resolves at `*.services.ai.azure.com`

`customSubDomainName` was not set on the Foundry account. It is mandatory — without it,
that endpoint does not exist at all and every stateful Foundry feature fails, including
the Anthropic Messages endpoint. It cannot be added after creation; recreate the account.

Check what you have:

```bash
az cognitiveservices account show \
  --name "$ANTHROPIC_FOUNDRY_RESOURCE" --resource-group rg-soc-triage-agent \
  --query "properties.endpoint" -o tsv
```

### Model deployment fails on `apply`

Almost always the **Anthropic Marketplace offer has not been accepted** on the
subscription. Accept it in the Foundry portal (Model catalog → Claude → Deploy → accept
terms), then re-apply. The two-pass workflow is in
[Deployment](deployment.md#accept-the-anthropic-marketplace-offer-first).

Second possibility: the region does not offer the model. Claude deploys as Global
Standard; `eastus2` and `swedencentral` are reliable.

### `401` / `403` from Foundry

```bash
az login
az account show          # right tenant? right subscription?
```

With `ANTHROPIC_FOUNDRY_API_KEY` blank, the agent authenticates as you, so you need the
**Azure AI User** role on the Foundry resource. Add your object id to
`analyst_principal_ids` and re-apply, or ask an administrator to grant it:

```bash
az ad signed-in-user show --query id -o tsv
```

A stale CLI token gives the same symptom — `az login` again before digging further.

### `429` during a batch

Pay-as-you-go quota for Claude on Foundry is **40 RPM / 40K input tokens per minute**.
Each triage makes several tool-augmented calls carrying raw EML and the full message data
model, so a handful of concurrent messages is enough.

Lower `concurrency` (the notebook uses `3`), triage fewer messages per run, or raise
capacity on the deployment.

### The wrong client: `FoundryChatClient` vs `AnthropicFoundryClient`

Claude on Foundry is served over the **Anthropic Messages** endpoint
(`https://<resource>.services.ai.azure.com/anthropic/v1/messages`), not the Responses
endpoint. `FoundryChatClient` targets Responses and is for the OpenAI-family models;
using it against a Claude deployment fails in confusing ways. `agent.py` uses
`AnthropicFoundryClient`.

---

## Sublime

### `401` with a key you just created

Two causes, in order of likelihood:

1. **Wrong region.** `SUBLIME_BASE_URL` must match your tenant's region. A valid key
   against the wrong regional host returns 401 or 404. The list is in
   [Configuration](configuration.md#sublime-security).
2. The key lacks the scope. Read access covers everything except mailbox actions.

Every Sublime error raised by this project includes the `X-Request-ID` header — that is
what Sublime support asks for.

### Message content comes back empty or redacted

Sublime redacts message content until an **access justification** is recorded. The agent
does this automatically via `ctx.ensure_justified()` before its first content read. If
you are calling `SublimeClient` directly, call `set_access_justification()` first.

### `recent_messages()` returns nothing

Usually correct behavior. The default window is five minutes, which is right for
monitoring and wrong for a demo tenant. Widen it:

```python
messages = session.recent_messages(lookback_minutes=1440, inbound_only=True)
```

`inbound_only=True` also filters out your own outbound and internal mail — if you are
testing by sending yourself a message from inside the tenant, it will not appear. Forward
the sample from an external address instead.

### A `KeyError` or empty field reading a Sublime response

Worth reporting. The endpoint paths and parameters in `sublime.py` come from Sublime's
published OpenAPI spec, but the **field names read out of the message data model, attack
score, ASA verdict and hunt results are inferred** and have not been checked against live
responses. Open an issue with the shape you actually got — that is one of the most useful
contributions available right now.

---

## Triage behavior

### Every message comes back `(triage failed)`

`triage()` catches all exceptions so one bad message cannot abort a batch — the failure
is in `result.error`, not raised:

```python
for r in results:
    if not r.ok:
        print(r.verdict.message_id, r.error)
```

Read the first one. It is usually a credential or endpoint problem from the sections
above, repeated once per message.

### `TypeError: Agent returned str, expected TriageVerdict`

The model returned prose instead of the structured schema. Structured output on MAF is
`options={"response_format": SomePydanticModel}`, read back from `response.value` — and
`ChatOptions` is a `TypedDict`, not a dataclass. If you edited `agent.py` or `run_options()`,
that is where to look. The raw text is truncated into the exception message.

### VirusTotal enrichment is skipped

Expected when `VT_API_KEY` is unset — `TriageSession.virustotal` is `None` and the tool
is unavailable. On the public tier you also get 4 requests/minute and 500/day, throttled
client-side, so the agent is instructed to spend that budget on indicators that could
change the verdict. Lookups are cached in `.cache/`; delete it to force fresh results.

### The agent seems to be following instructions inside an email

Report it — see [SECURITY.md](../SECURITY.md). Then check that Prompt Shields is actually
configured on the deployment. Claude deployments on Foundry have **no content filter by
default**, unlike Azure OpenAI models. The in-code spotlighting in `tools.spotlight()` is
the other half of the defense, not the whole of it. See
[Deployment → content filtering](deployment.md#content-filtering).

---

## Still stuck

Open an issue with: the failing command, the full traceback, `pip show
agent-framework-core agent-framework-anthropic`, and — for anything Azure — the output of
`az account show`. Redact subscription ids, tenant ids, keys and message content.
