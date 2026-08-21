# Contributing

Thanks for taking a look. This is a demo/reference implementation of an LLM-driven SOC
email triage workflow — the teaching value matters as much as the code, so clarity and
honesty about what is proven are held to the same bar as correctness.

## Ground rules specific to this project

1. **Deterministic logic stays deterministic.** Header parsing, IOC extraction,
   defanging, quota arithmetic and HTML escaping are computed in Python and handed to
   the model as fact. Do not move that work into a prompt.
2. **Safety switches default closed.** `ALLOW_MAILBOX_ACTIONS` and `ALLOW_VT_SUBMIT`
   default to `false`, and the mailbox action tool is not registered with the agent
   unless explicitly enabled. A PR that changes a default to open will not be merged.
3. **Lookup-only VirusTotal.** Submission endpoints are deliberately unimplemented.
   Uploading a customer's attachment to VT publishes it to every VT enterprise
   subscriber.
4. **Untrusted content stays marked.** Anything derived from an email must pass through
   `tools.spotlight()` before it reaches the model.
5. **Never commit real mail.** No message bodies, recipient addresses, live IOCs, tenant
   IDs or subscription IDs — in code, in tests, in fixtures, or in notebook outputs.
   Clear notebook outputs before committing:
   `jupyter nbconvert --clear-output --inplace notebooks/*.ipynb`
6. **Say what is unverified.** Parts of this codebase have never run against a live
   tenant (see [Project status](README.md#project-status)). If you verify one, update
   that section. If you add something unverified, say so there too.

## Setup

```bash
git clone https://github.com/iknowjason/foundragent.git && cd foundragent
python -m venv .venv && source .venv/bin/activate
pip install -e ".[notebook,msticpy,dev]"
pytest
```

See [docs/development.md](docs/development.md) for the layout and for how to add a tool.

## Tests

The suite covers the parts that must be right regardless of model behavior: header
forensics, IOC handling, quota prioritization, and HTML escaping of attacker-controlled
strings. New deterministic logic needs a test. Agent prompt changes do not — but say in
the PR how you checked the behavior, because CI cannot.

```bash
pytest              # all
pytest -q tests/test_headers.py
```

Tests must not make network calls or require credentials.

## Pull requests

- Branch from `main`, keep the change focused, and explain the *why* in the description.
- Run `pytest` before opening. CI runs the same suite on 3.11–3.13.
- Terraform changes: run `terraform fmt` and `terraform validate`, and note in the PR
  whether you ran `terraform apply` against a real subscription — that distinction is
  tracked deliberately.
- Documentation-only PRs are welcome and do not need an issue first.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
