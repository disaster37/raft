# Contributing

## Workflow

1. Fork and create a feature branch.
2. Follow the coding conventions below.
3. Run the CI gate before opening a PR.
4. Keep docs, config samples, and ADRs in sync with code changes.

## Coding conventions

- Never concatenate strings with `+`; use `fmt.Sprintf`.
- Wrap errors with `fmt.Errorf("...: %w", err)`.
- Standard library `testing` only (no testify, no ginkgo).
- Table-driven tests where appropriate.
- No dead/unused symbols; `golangci-lint` `unused` must pass.
- `gofmt` + `goimports` with local prefix `github.com/disaster37/go-raft`.
- Integration tests must use `testutil.FreeListener(t)` and timed shutdown in
  `t.Cleanup`; never probe-then-close ports.
- Enforce `0700` directories and `0600` keys/DB/node-id.

## CI gate

```bash
dagger call -m ./dagger --src . ci export --path out
```

Minimum local fallback:

```bash
gofmt -l .
goimports -l -local github.com/disaster37/go-raft .
go build ./...
go vet ./...
go test -race -covermode=atomic ./...
golangci-lint run
```

## Pull requests

- Describe the behaviour change and any migration impact.
- Include tests for new behaviour and failure paths.
- Update `docs/`, `config/config.app.yaml.sample`, and ADRs when relevant.
