package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/raft/internal/dagger"
)

const (
	golangImage         = "golang:1.27-bookworm"
	golangciLintVersion = "v2.14.0"
	govulncheckVersion  = "v1.9.0"
	gosecVersion        = "v2.30.0"
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
	return m.checkCoverageFile(ctx, file, minTotal)
}

func (m *Raft) checkCoverageFile(ctx context.Context, coverage *dagger.File, minTotal float64) (string, error) {
	script := `grep -v '/examples/' coverage.out | grep -v '/test/' > coverage.filtered.out
go tool cover -func=coverage.filtered.out | tail -1
awk 'NR>1 { split($1,a,":"); file=a[1]; n=split(file,parts,"/"); pkg=parts[n-1]; stmts=$2; count=$3; total[pkg]+=stmts; if (count+0>0) covered[pkg]+=stmts } END { for (pkg in total) printf "pkg %s %.1f\n", pkg, 100*covered[pkg]/total[pkg] }' coverage.filtered.out`
	out, err := m.base().WithFile("coverage.out", coverage).WithExec([]string{"sh", "-c", script}).Stdout(ctx)
	if err != nil {
		return "", err
	}
	var total float64
	required := map[string]float64{"config": 95.0, "discovery": 95.0, "keyring": 95.0}
	found := map[string]float64{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "total:") {
			if _, err := fmt.Sscanf(line, "total:\t(statements)\t%f%%", &total); err != nil {
				return "", fmt.Errorf("parse coverage: %w", err)
			}
			continue
		}
		var pkg string
		var pct float64
		if _, err := fmt.Sscanf(line, "pkg %s %f", &pkg, &pct); err == nil {
			found[pkg] = pct
		}
	}
	if total < minTotal {
		return "", fmt.Errorf("coverage %.1f%% is below %.1f%%", total, minTotal)
	}
	for pkg, min := range required {
		pct, ok := found[pkg]
		if !ok {
			return "", fmt.Errorf("coverage for package %s not found", pkg)
		}
		if pct < min {
			return "", fmt.Errorf("coverage for package %s is %.1f%% (below %.1f%%)", pkg, pct, min)
		}
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
	cmd := fmt.Sprintf("go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@%s && gomarkdoc ./... --exclude-dirs ./test/... --output docs/api.md", gomarkdocVersion)
	if check {
		cmd = fmt.Sprintf("go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@%s && gomarkdoc ./... --exclude-dirs ./test/... --output docs/api.md --check", gomarkdocVersion)
	}
	ctr, err := m.base().WithExec([]string{"sh", "-c", cmd}).Sync(ctx)
	if err != nil {
		return nil, err
	}
	return ctr.File("docs/api.md"), nil
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
	coverage, err := m.TestRace(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := m.checkCoverageFile(ctx, coverage, 90.0); err != nil {
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
