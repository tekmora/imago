// Copyright 2026 Lusoris
package imageless_test

import (
	"encoding/json/v2"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cordanaLLM/imago"
	"github.com/cordanaLLM/imago/pkg/flavors"
	"github.com/cordanaLLM/imago/pkg/imageless"
)

// Refresh the apply script golden with go test ./pkg/imageless -run '^TestApplyScriptsGolden$' -update.
var update = flag.Bool("update", false, "rewrite testdata/apply-scripts.golden.txt")

var (
	applyGolden  = filepath.Join("testdata", "apply-scripts.golden.txt")
	versionsFile = filepath.Join("..", "..", "versions.json")
	pinExport    = regexp.MustCompile(`(?m)^export ([A-Z_][A-Z0-9_]*)='(?:[^']|'\\'')*'$`)
)

func maskApplyPinValues(t *testing.T, script string, mapping map[string]string) string {
	t.Helper()
	header, env, found := strings.Cut(script, "# Environment configuration\n")
	if !found {
		return script
	}
	env, pipeline, found := strings.Cut(env, "\n# Execution pipeline\n")
	require.True(t, found, "apply script has no execution pipeline")
	env = pinExport.ReplaceAllStringFunc(env, func(export string) string {
		name := pinExport.FindStringSubmatch(export)[1]
		if path, ok := mapping[name]; ok {
			return "export " + name + "='" + path + "'"
		}
		return export
	})
	return header + "# Environment configuration\n" + env + "\n# Execution pipeline\n" + pipeline
}

func pinEnvMapping(t *testing.T) map[string]string {
	t.Helper()
	var mapping map[string]string
	require.NoError(t, json.Unmarshal(imago.PinEnvMapping, &mapping))
	return mapping
}

func TestApplyScriptsGolden(t *testing.T) {
	mapping := pinEnvMapping(t)
	modes := []struct {
		name string
		opts imageless.ApplyOptions
	}{
		{"full", imageless.ApplyOptions{}},
		{"skip-cleanup", imageless.ApplyOptions{SkipCleanup: true}},
		{"dry-run", imageless.ApplyOptions{DryRun: true}},
	}
	var sb strings.Builder
	for _, fl := range flavors.All() {
		for _, m := range modes {
			opts := m.opts
			opts.FlavorID = fl.ID
			opts.VersionsPath = versionsFile
			script, err := imageless.GenerateApplyScript(opts)
			require.NoError(t, err)
			sb.WriteString("=== " + fl.ID + " " + m.name + "\n" + maskApplyPinValues(t, script, mapping))
		}
	}
	if *update {
		require.NoError(t, os.MkdirAll("testdata", 0o750))
		require.NoError(t, os.WriteFile(applyGolden, []byte(sb.String()), 0o600))
	}
	want, err := os.ReadFile(applyGolden)
	require.NoError(t, err, "golden file missing; run with -update to create it")
	require.Equal(t, string(want), sb.String())
}

func TestApplyGoldenSurvivesPinBump(t *testing.T) {
	opts := imageless.ApplyOptions{FlavorID: "base-generic", VersionsPath: versionsFile}
	baseline, err := imageless.GenerateApplyScript(opts)
	require.NoError(t, err)
	document := readVersionsDocument(t)
	tools := document["tools"].(map[string]any)
	bumped := tools["cdebug"].(string) + "-test.1"
	tools["cdebug"] = bumped
	opts.VersionsPath = writeVersionsDocument(t, document)
	script, err := imageless.GenerateApplyScript(opts)
	require.NoError(t, err)
	require.Contains(t, script, "\nexport CDEBUG_VERSION='"+bumped+"'\n")
	mapping := pinEnvMapping(t)
	normalized := maskApplyPinValues(t, script, mapping)
	require.Equal(t, maskApplyPinValues(t, baseline, mapping), normalized)
	want, err := os.ReadFile(applyGolden)
	require.NoError(t, err)
	first, _, found := strings.Cut(string(want), "=== base-generic skip-cleanup\n")
	require.True(t, found)
	require.Equal(t, first, "=== base-generic full\n"+normalized)
}

func TestApplyExportsManifestPinValues(t *testing.T) {
	script, err := imageless.GenerateApplyScript(imageless.ApplyOptions{FlavorID: "base-generic", VersionsPath: versionsFile})
	require.NoError(t, err)
	document := readVersionsDocument(t)
	var expected []string
	for name, keyPath := range pinEnvMapping(t) {
		var value any = document
		for key := range strings.SplitSeq(keyPath, ".") {
			value = value.(map[string]any)[key]
		}
		quoted := "'" + strings.ReplaceAll(value.(string), "'", `'\''`) + "'"
		expected = append(expected, "export "+name+"="+quoted)
	}
	slices.Sort(expected)
	require.Len(t, expected, 35)
	require.Equal(t, expected, pinExport.FindAllString(script, -1))
}
