# SecretLens

SecretLens is a local-first defensive tool for finding likely credentials in source files, configuration, and notes before they reach a repository. The browser dashboard runs entirely on the client and redacts matched values in its report. The Docker CLI scans an authorized local file or directory.

## Browser dashboard and GitHub Pages

Open `index.html` locally or publish this directory as a GitHub Pages repository. The included `.github/workflows/pages.yml` deploys the static dashboard from the `main` branch when GitHub Pages is configured to use GitHub Actions.

1. Drop one or more text files into the dashboard, or paste content.
2. Choose **Run secret scan**.
3. Review the redacted findings and remediation path.
4. Export the JSON report if needed.

No file contents are sent to a server. The static page has no backend.

## Docker CLI

Build from this directory:

```sh
docker build -t secretlens .
```

Scan a local directory read-only and write the report to the host:

```sh
mkdir -p reports
docker run --rm \
  -v "$PWD/samples:/data:ro" \
  -v "$PWD/reports:/reports" \
  secretlens /data --output /reports/report.json
```

The included sample contains synthetic values only. Never paste a live credential into a public issue, chat, or repository. Scan only files you are authorized to inspect. A match is a review signal, not proof that a credential is active.

## Detectors

The initial detectors cover private-key headers, AWS access keys, GitHub tokens, Slack tokens, JWT-shaped tokens, and named long-value assignments such as `API_KEY` or `PASSWORD`. Detection is heuristic and can miss provider-specific formats or produce false positives.

## License

MIT. See [LICENSE](LICENSE).
