# Dagger CI

The `dagger/` module wraps `github.com/disaster37/dagger-library-go` and runs
the full merge gate inside containers.

## Commands

```bash
# Full CI (format, lint, vulncheck, gosec, coverage, build, docs)
dagger call -m ./dagger --src . ci --static=true export --path out

# Individual steps
dagger call -m ./dagger --src . format-check
dagger call -m ./dagger --src . lint
dagger call -m ./dagger --src . vulncheck
dagger call -m ./dagger --src . gosec
dagger call -m ./dagger --src . test
dagger call -m ./dagger --src . test-race export --path coverage.out
dagger call -m ./dagger --src . coverage --min-total 90
dagger call -m ./dagger --src . build --static=true export --path bin
dagger call -m ./dagger --src . docs --check=false export --path docs/api.md
dagger call -m ./dagger --src . release --version v0.1.0 --github-token env:GITHUB_TOKEN
```

## Pins

| Tool | Version |
|---|---|
| Go image | `golang:1.27-bookworm` |
| Dagger engine | `v0.21.8` |
| `golangci-lint` | `v2.14.0` |
| `govulncheck` | `v1.9.0` |
| `gosec` | `v2.30.0` |
| `gomarkdoc` | `v1.1.0` |
| `dagger-library-go/golang` | `2.0.12` (`69b57f8ff6f970a8e28480741f14c58ae4aac014`) |
| `dagger-library-go/codecov` | `2.0.19` (`d7e755bbd544480c8a96adc2204d70cf40ee6c0c`) |

## Updating dependencies

1. Update the `source` and `pin` in `dagger/dagger.json`.
2. Run `dagger develop -m ./dagger` to regenerate bindings.
3. Run `dagger call -m ./dagger --src . ci` and commit the regenerated
   `dagger/dagger.gen.go` and `dagger/internal/dagger/*.gen.go`.

## Troubleshooting

- **Engine cannot start / cloud URL returns HTML**: unset
  `_EXPERIMENTAL_DAGGER_RUNNER_HOST`, `DAGGER_CLOUD_URL`, and
  `DAGGER_CLOUD_TOKEN` to use the local Docker engine.
- **GitHub API TLS timeout during `vulncheck`/`lint`**: the upstream
  `golang` module queries GitHub for the latest release when the tool is not
  already on `PATH`. The module preinstalls both tools into `/usr/local/bin`
  so the lookup is skipped. If the network is still unavailable, run the
  local fallback below.
- **Coverage gate**: the gate excludes `examples/` and `test/` from the
  statement total; library packages must stay at or above 90% overall and
  `config`, `discovery`, and `keyring` at or above 95%.

## Local fallback

When Dagger cannot run (no Docker daemon or no network):

```bash
gofmt -l .
goimports -l -local github.com/disaster37/go-raft .
go build ./...
go vet ./...
go test -race -covermode=atomic ./...
golangci-lint run
for d in examples/*/; do CGO_ENABLED=0 go build -o /tmp/$(basename "$d") "./$d"; done
```
