package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/raft/internal/dagger"
)

const (
	golangImage         = "golang:1.27-bookworm"
	golangciLintVersion = "v2.12.2"
	govulncheckVersion  = "v1.1.4"
	gosecVersion        = "v2.22.2"
	gomarkdocVersion    = "v1.1.0"
)

// Raft is the Dagger CI module for github.com/disaster37/raft.
type Raft struct {
	Src *dagger.Directory
}

// New initializes the raft CI module.
func New(
	// The source directory.
	// +required
	src *dagger.Directory,
) *Raft {
	return &Raft{Src: src}
}

func (m *Raft) base() *dagger.Container {
	return dag.Container().From(golangImage).WithDirectory("/src", m.Src).WithWorkdir("/src")
}

// FormatCheck fails when any Go file is not gofmt-formatted.
func (m *Raft) FormatCheck(ctx context.Context) error {
	_, err := m.base().WithExec([]string{"sh", "-c", "test -z \"$(gofmt -s -l .)\""}).Sync(ctx)
	return err
}

// Lint runs golangci-lint.
func (m *Raft) Lint(ctx context.Context) (string, error) {
	base := m.base().WithExec([]string{"sh", "-c", fmt.Sprintf("GOBIN=/usr/local/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@%s", golangciLintVersion)})
	return dag.Golang(m.Src, dagger.GolangOpts{Base: base}).Lint(ctx)
}

// Vulncheck runs govulncheck.
func (m *Raft) Vulncheck(ctx context.Context) (string, error) {
	base := m.base().WithExec([]string{"sh", "-c", fmt.Sprintf("GOBIN=/usr/local/bin go install golang.org/x/vuln/cmd/govulncheck@%s", govulncheckVersion)})
	return dag.Golang(m.Src, dagger.GolangOpts{Base: base}).Vulncheck(ctx)
}

// Gosec runs gosec.
func (m *Raft) Gosec(ctx context.Context) (string, error) {
	return m.base().WithExec([]string{"sh", "-c", fmt.Sprintf("go install github.com/securego/gosec/v2/cmd/gosec@%s && gosec -exclude-generated -quiet ./...", gosecVersion)}).Stdout(ctx)
}

// Test runs the unit tests.
func (m *Raft) Test(ctx context.Context) (*dagger.File, error) {
	return dag.Golang(m.Src).Test(), nil
}

// TestRace runs go vet and the race-enabled test suite.
func (m *Raft) TestRace(ctx context.Context) (*dagger.File, error) {
	ctr := m.base().
		WithExec([]string{"go", "vet", "./..."}).
		WithExec([]string{"go", "test", "-race", "-coverprofile=coverage.out", "-covermode=atomic", "./..."}).
		WithExec([]string{"sh", "-c", "go test -run=^$ -fuzz=FuzzParseLegacyPeers -fuzztime=5s ./discovery && go test -run=^$ -fuzz=FuzzPodSANs -fuzztime=5s ./discovery && go test -run=^$ -fuzz=FuzzParsePEMCert -fuzztime=5s ./pki && go test -run=^$ -fuzz=FuzzFixPKCS1Key -fuzztime=5s ./pki && go test -run=^$ -fuzz=FuzzKeyringJSON -fuzztime=5s ./keyring && go test -run=^$ -fuzz=FuzzCommandDecode -fuzztime=5s ./fsm"})
	return ctr.File("coverage.out"), nil
}

// Coverage enforces the minimum statement coverage.
func (m *Raft) Coverage(ctx context.Context, minTotal float64) (string, error) {
	file, err := m.TestRace(ctx)
	if err != nil {
		return "", err
	}
	out, err := m.base().WithFile("coverage.out", file).WithExec([]string{"sh", "-c", "grep -v '/examples/' coverage.out | grep -v '/test/' > coverage.filtered.out && go tool cover -func=coverage.filtered.out | tail -1"}).Stdout(ctx)
	if err != nil {
		return "", err
	}
	var total float64
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "total:\t(statements)\t%f%%", &total); err != nil {
		return "", fmt.Errorf("parse coverage: %w", err)
	}
	if total < minTotal {
		return "", fmt.Errorf("coverage %.1f%% is below %.1f%%", total, minTotal)
	}
	return out, nil
}

// Build compiles every example into bin/examples.
func (m *Raft) Build(ctx context.Context, static bool) (*dagger.Directory, error) {
	ctr := m.base()
	if static {
		ctr = ctr.WithEnvVariable("CGO_ENABLED", "0")
	} else {
		ctr = ctr.WithEnvVariable("CGO_ENABLED", "1")
	}
	ctr = ctr.WithExec([]string{"sh", "-c", "mkdir -p bin/examples && for d in examples/*/; do go build -o bin/examples/$(basename $d) ./$d; done"})
	return ctr.Directory("bin"), nil
}

// Docs generates docs/api.md with gomarkdoc.
func (m *Raft) Docs(ctx context.Context, check bool) (*dagger.File, error) {
	cmd := fmt.Sprintf("go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@%s && gomarkdoc ./... --output docs/api.md", gomarkdocVersion)
	if check {
		cmd = fmt.Sprintf("go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@%s && gomarkdoc ./... --check", gomarkdocVersion)
	}
	if _, err := m.base().WithExec([]string{"sh", "-c", cmd}).Sync(ctx); err != nil {
		return nil, err
	}
	return m.base().File("docs/api.md"), nil
}

// Ci runs the full CI pipeline.
func (m *Raft) Ci(ctx context.Context, static bool) (*dagger.Directory, error) {
	if err := m.FormatCheck(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Lint(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Vulncheck(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Gosec(ctx); err != nil {
		return nil, err
	}
	if _, err := m.Coverage(ctx, 90.0); err != nil {
		return nil, err
	}
	bin, err := m.Build(ctx, static)
	if err != nil {
		return nil, err
	}
	docs, err := m.Docs(ctx, false)
	if err != nil {
		return nil, err
	}
	coverage, err := m.TestRace(ctx)
	if err != nil {
		return nil, err
	}
	return dag.Directory().WithFile("coverage.out", coverage).WithFile("docs/api.md", docs).WithDirectory("bin", bin), nil
}

// Release validates the version and publishes a GitHub release.
func (m *Raft) Release(ctx context.Context, version string, githubToken *dagger.Secret) (string, error) {
	if !strings.HasPrefix(version, "v") || strings.Count(version, ".") != 2 {
		return "", fmt.Errorf("version %q is not a clean semver tag", version)
	}
	if _, err := m.Ci(ctx, true); err != nil {
		return "", err
	}
	bin, err := m.Build(ctx, true)
	if err != nil {
		return "", err
	}
	return m.base().WithSecretVariable("GITHUB_TOKEN", githubToken).WithDirectory("bin", bin).WithExec([]string{"sh", "-c", fmt.Sprintf("gh release create %s --generate-notes bin/examples/*", version)}).Stdout(ctx)
}
