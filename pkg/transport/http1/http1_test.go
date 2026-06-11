package http1_test

import (
	"testing"

	"phoenix/pkg/testutils"
)

func TestHTTP1Transport(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportFunctionalSuite(t, "http1", scenarios)
}

func BenchmarkHTTP1Transport(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportBenchmarkSuite(b, "http1", scenarios)
}

func TestHTTP1Transport_E2E(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunE2EFunctionalSuite(t, "http1", scenarios)
}

func BenchmarkHTTP1Transport_E2E(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunE2EBenchmarkSuite(b, "http1", scenarios)
}
