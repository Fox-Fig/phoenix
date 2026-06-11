package ssh_test

import (
	"testing"

	"phoenix/pkg/testutils"
)

func TestSSHTransport(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportFunctionalSuite(t, "ssh", scenarios)
}

func BenchmarkSSHTransport(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunTransportBenchmarkSuite(b, "ssh", scenarios)
}

func TestSSHTransport_E2E(t *testing.T) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunE2EFunctionalSuite(t, "ssh", scenarios)
}

func BenchmarkSSHTransport_E2E(b *testing.B) {
	scenarios := testutils.GenerateTestScenarios()
	testutils.RunE2EBenchmarkSuite(b, "ssh", scenarios)
}
