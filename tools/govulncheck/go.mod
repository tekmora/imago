// Copyright 2026 Lusoris
// Pins govulncheck for the security-scans workflow, apart from the imago module so
// that its dependencies do not raise the versions imago builds with. Renovate's gomod
// manager updates it. Run from the repository root:
//   go -C tools/govulncheck tool govulncheck -C "$PWD" ./...
module github.com/cordanaLLM/imago/tools/govulncheck

go 1.27.3

tool golang.org/x/vuln/cmd/govulncheck

require (
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/telemetry v0.0.0-20261116191925-e77a43154acb // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.org/x/vuln v1.10.0 // indirect
)
