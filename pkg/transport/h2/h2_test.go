package h2_test

import (
	"testing"

	"phoenix/pkg/testutils"
)

func TestH2Transport(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportFunctionalSuite(t, "h2", scenarios)
}

func BenchmarkH2Transport(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportBenchmarkSuite(b, "h2", scenarios)
}

func TestH2Transport_E2E(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunE2EFunctionalSuite(t, "h2", scenarios)
}

func BenchmarkH2Transport_E2E(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunE2EBenchmarkSuite(b, "h2", scenarios)
}
