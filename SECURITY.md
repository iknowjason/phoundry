# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/iknowjason/foundragent/security/advisories/new)
on this repository. Expect an acknowledgement within a few days.

Include what you can: affected version or commit, reproduction steps, and what an
attacker gets out of it.

## Scope

This project is a demo/reference implementation, not a supported product. It is still
worth reporting anything in these categories, because the failure modes are the
interesting part of the design:

- **Prompt injection that survives spotlighting** — attacker-authored email content that
  causes the agent to take an action, suppress a finding, or emit a false verdict.
  `tools.spotlight()` and the system prompt are the in-code defense; Prompt Shields is
  the deployment-layer defense. Bypasses of either are in scope.
- **Tool-boundary escapes** — anything that reaches `action_message` while
  `ALLOW_MAILBOX_ACTIONS=false`, or that causes a Sublime or VirusTotal call the analyst
  did not intend.
- **Secret or data leakage** — credentials, message content, recipient addresses or IOCs
  written to logs, reports, notebook outputs, cache files, or model context that should
  not carry them.
- **Injection in the report layer** — attacker-controlled strings escaping HTML or
  Markdown escaping in `report.py` and executing in the analyst's notebook.
- **Unsafe defaults** — any path where a safety switch effectively defaults open.

## Out of scope

- Vulnerabilities in Microsoft Foundry, Sublime Security, VirusTotal or the Microsoft
  Agent Framework themselves — report those to the respective vendors.
- Model output being wrong. This is a triage aid with a human in the loop; an incorrect
  verdict is a quality issue, not a vulnerability. Open a normal issue.
- Anything requiring an already-compromised analyst workstation.

## Operating this safely

If you deploy this against a real mail tenant, three things matter more than the rest:

1. Keep `ALLOW_MAILBOX_ACTIONS=false` unless you have a specific reason and a reviewed
   process. There is deliberately no "apply all".
2. Authenticate as a person (`az login`), not a shared service principal, so Foundry's
   audit log and Sublime's access justification name a human.
3. Configure Prompt Shields on the Claude deployment. Claude deployments on Foundry have
   **no content filter by default**, unlike Azure OpenAI models — and this agent feeds
   attacker-authored text to a tool-calling model. See
   [docs/deployment.md](docs/deployment.md#content-filtering).
