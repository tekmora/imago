// Copyright 2026 Lusoris
package imageless_test

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cordanaLLM/imago/pkg/imageless"
)

func TestGenerateApplyScript(t *testing.T) {
	opts := imageless.ApplyOptions{
		FlavorID:     "docker-generic",
		VersionsPath: versionsFile,
	}

	script, err := imageless.GenerateApplyScript(opts)
	require.NoError(t, err)

	assert.Contains(t, script, "#!/usr/bin/env bash")
	assert.Contains(t, script, "export FLAVOR=\"docker-generic\"")
	assert.Contains(t, script, "40-docker-runtime.sh")
}

func TestGenerateApplyScriptDryRun(t *testing.T) {
	t.Chdir(t.TempDir())
	opts := imageless.ApplyOptions{
		FlavorID: "base-generic",
		DryRun:   true,
	}

	script, err := imageless.GenerateApplyScript(opts)
	require.NoError(t, err)

	assert.Contains(t, script, "DRY-RUN")
	assert.Contains(t, script, "[SIMULATED] 00-base-strip.sh")
}

func TestGenerateApplyScriptRejectsMissingManifest(t *testing.T) {
	t.Chdir(t.TempDir())
	script, err := imageless.GenerateApplyScript(imageless.ApplyOptions{FlavorID: "base-generic"})
	require.ErrorContains(t, err, "read versions.json")
	assert.Empty(t, script)
}

func readVersionsDocument(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(versionsFile)
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(data, &document))
	return document
}

func writeVersionsDocument(t *testing.T, document map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "versions.json")
	data, err := json.Marshal(document)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestGenerateApplyScriptRejectsInvalidManifestPins(t *testing.T) {
	t.Run("missing mapped key", func(t *testing.T) {
		document := readVersionsDocument(t)
		delete(document["tools"].(map[string]any), "enroot")
		path := writeVersionsDocument(t, document)
		script, err := imageless.GenerateApplyScript(imageless.ApplyOptions{FlavorID: "base-generic", VersionsPath: path})
		require.ErrorContains(t, err, path)
		require.ErrorContains(t, err, "tools.enroot (ENROOT_VERSION)")
		require.Empty(t, script)
	})
	t.Run("non-string manifest pin", func(t *testing.T) {
		document := readVersionsDocument(t)
		document["tools"].(map[string]any)["enroot"] = false
		path := writeVersionsDocument(t, document)
		script, err := imageless.GenerateApplyScript(imageless.ApplyOptions{FlavorID: "base-generic", VersionsPath: path})
		require.ErrorContains(t, err, path)
		require.ErrorContains(t, err, "enroot")
		require.Empty(t, script)
	})
}

func TestGenerateApplyScriptQuotesManifestPins(t *testing.T) {
	document := readVersionsDocument(t)
	document["tools"].(map[string]any)["cdebug"] = "one'$name\ntwo"
	path := writeVersionsDocument(t, document)
	script, err := imageless.GenerateApplyScript(imageless.ApplyOptions{FlavorID: "base-generic", VersionsPath: path})
	require.NoError(t, err)
	require.Contains(t, script, "export CDEBUG_VERSION='one'\\''$name\ntwo'\n")
	require.Contains(t, maskApplyPinValues(t, script, pinEnvMapping(t)), "export CDEBUG_VERSION='tools.cdebug'\n")
}

func TestGenerateBootCommand(t *testing.T) {
	cfg := imageless.MicroVMBootConfig{
		FlavorID:   "ai-infer-generic",
		KernelPath: "/custom/vmlinuz",
		InitrdPath: "/custom/initrd.img",
	}

	cmd, err := imageless.GenerateBootCommand(cfg)
	require.NoError(t, err)

	assert.Contains(t, cmd, "qemu-system-x86_64")
	assert.Contains(t, cmd, "-kernel '/custom/vmlinuz'")
	assert.Contains(t, cmd, "-initrd '/custom/initrd.img'")
	assert.Contains(t, cmd, "transparent_hugepage=madvise")
}
