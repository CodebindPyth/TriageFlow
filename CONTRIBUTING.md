# Contributing to TriageFlow

Thanks for helping improve TriageFlow! Contributions are welcome through GitHub forks and pull requests. New users can start with [QUICKSTART_EL.md](QUICKSTART_EL.md) for the step-by-step Greek usage guide.

## Before you start

- Check existing issues and pull requests to avoid duplicate work.
- For a significant feature, open an issue first to discuss the proposed behavior.
- Never include real target lists, scan output, screenshots, credentials, API keys, private data, or other sensitive artifacts in an issue or pull request.
- Test only systems you own or are explicitly authorized to assess. Use local labs or deliberately vulnerable test applications for tests.

## Pull request workflow

1. Fork the repository on GitHub.
2. Create a short, descriptive branch from main, for example feature/cve-inventory.
3. Make a focused change and update the README when CLI behavior or output changes.
4. Run the checks below.
5. Open a pull request against this repository's main branch. Explain the motivation, the implementation, how it was tested, and any limitations.

## Local checks

    python -m unittest discover -s tests -v
    python -m py_compile triageflow.py triageflow_enrichment.py triageflow_reports.py
    python triageflow.py --help

The project aims to use the Python standard library for orchestration and enrichment. If a dependency is necessary, explain why and update requirements.txt.

## Code expectations

- Keep changes readable, narrowly scoped, and compatible with Python 3.10+.
- Handle timeouts, malformed tool output, and unavailable external services without silently claiming success.
- Keep external requests bounded and document any new network behavior.
- Treat fingerprint matches and CVE keyword results as leads requiring manual verification.
- Never add credential spraying, password brute forcing, or automatic login submissions.
- Do not commit generated scan output or any secrets.

## Reporting issues

Include your Python and relevant tool versions, exact command with sensitive values removed, expected behavior, actual behavior, and a minimal reproduction. Redact target names and tokens unless they are public test fixtures.

By submitting a contribution, you confirm that you have the right to submit it under the project's MIT license.
