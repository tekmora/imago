// Copyright 2026 Lusoris
package imageless

import (
	"context"
	"encoding/json/v2"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cordanaLLM/imago"
)

const emptyPinPath = "drivers.nvidia.cuda_legacy"

var emptyPinFixture = flag.String("empty-pin-fixture", "", "manifest path for the isolated resolver test")

func TestGenerateApplyScriptRejectsEmptyResolvedPin(t *testing.T) {
	if *emptyPinFixture != "" {
		assertEmptyPinStopsGeneration(t, *emptyPinFixture)
		return
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "versions.json"))
	require.NoError(t, err)
	var document map[string]any
	require.NoError(t, json.Unmarshal(data, &document))
	document["drivers"].(map[string]any)["nvidia"].(map[string]any)["cuda_legacy"] = ""

	t.Run("resolver", func(t *testing.T) {
		value, err := resolveManifestPin(document, emptyPinPath)
		require.ErrorContains(t, err, emptyPinPath)
		require.Empty(t, value)
	})
	t.Run("generation", func(t *testing.T) {
		fixture := filepath.Join(t.TempDir(), "versions.json")
		encoded, err := json.Marshal(document)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(fixture, encoded, 0o600))

		binary, err := os.Executable()
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestGenerateApplyScriptRejectsEmptyResolvedPin$", "-empty-pin-fixture="+fixture)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
	})
}

func assertEmptyPinStopsGeneration(t *testing.T, path string) {
	t.Helper()
	// The child process changes the embedded schema before the manifest loader caches it.
	var schema map[string]any
	require.NoError(t, json.Unmarshal(imago.VersionsSchema, &schema))
	leaf := schema
	for key := range strings.SplitSeq(emptyPinPath, ".") {
		leaf = leaf["properties"].(map[string]any)[key].(map[string]any)
	}
	delete(leaf, "minLength")
	encoded, err := json.Marshal(schema)
	require.NoError(t, err)
	imago.VersionsSchema = encoded

	script, err := GenerateApplyScript(ApplyOptions{FlavorID: "base-generic", VersionsPath: path})
	require.ErrorContains(t, err, "imageless: "+path+": "+emptyPinPath+" (CUDA_LEGACY):")
	require.ErrorContains(t, err, emptyPinPath+" must not be empty")
	require.Empty(t, script)
}
