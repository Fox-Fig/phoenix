package h2_test

import (
	"testing"

	"phoenix/pkg/testutils"
)

func TestH2Transport(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportFunctionalSuite(t, scenarios)
}

func BenchmarkH2Transport(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportBenchmarkSuite(b, scenarios)
}
