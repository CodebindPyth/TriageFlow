# Optional AI-assisted triage

TriageFlow's normal scanning workflow remains dependency-free. The optional AI layer reviews **saved output artifacts only** and writes an advisory prioritization report. It does not have tools, execute commands, or contact target systems.

## Model choice

The default is `gpt-6-astra`, configurable through `TRIAGEFLOW_AI_MODEL`. If your OpenAI API account cannot access that model, set a model ID available to your project, such as:

- `gpt-6.1-sol` for a strong reasoning/cost balance.
- `gpt-6-luna` for lower-cost, high-volume summarization.

Availability depends on your OpenAI API account. A ChatGPT subscription does not automatically provide API credits.

## Setup

Set your environment variables, then run the AI triage command against an existing results folder:

```bash
export OPENAI_API_KEY="your-api-key"
export TRIAGEFLOW_AI_MODEL="gpt-6-astra"
python3 triageflow.py --ai-triage ./triageflow-results/run-folder
```

Windows PowerShell:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:TRIAGEFLOW_AI_MODEL = "gpt-6-astra"
python .\triageflow.py --ai-triage .\triageflow-results\run-folder
```

Keep the API key out of the repository, CLI arguments, scan artifacts, and screenshots. Prefer environment variables or a secret manager. The command does **not** launch a scan. It writes `ai-triage.json` and `ai-triage.md`.

The implementation sends bounded subsets of `summary.json`, `asset-inventory.csv`, `software-inventory.csv`, `nuclei-findings.jsonl`, `cve-candidates.json`, and `login-panels.csv`. Those files can contain target names and scanner metadata. Do not send confidential or third-party data to an external API unless your authorization and data-handling policy allow it.

AI output is a prioritization aid, not proof of exploitability. Confirm CVE ranges in vendor advisories and validate claims against the cited artifacts. The model cannot run tools or perform intrusive tests.

## API implementation

Uses the OpenAI Responses API with schema-constrained JSON output and local validation, with no new Python dependencies. See the official [models catalog](https://developers.openai.com/api/docs/models), [Responses API](https://developers.openai.com/api/reference/responses/overview), and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).
