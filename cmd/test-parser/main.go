package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type TestResult struct {
	Protocol string
	Scenario string
	Status   string
	Duration string
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	// Regex for finishing a test: --- PASS: TestH2Transport/Scenario_Name (0.50s)
	resultRegex := regexp.MustCompile(`^\s*--- (PASS|FAIL):\s+Test(H2|HTTP1|SSH)Transport(?:_E2E)?/([^ ]+)\s+\(([^)]+)\)`)

	var results []*TestResult
	var failedLogs []string
	collectingFail := false

	fmt.Println("Running Functional Tests...")
	fmt.Println(strings.Repeat("=", 80))

	for scanner.Scan() {
		line := scanner.Text()

		if matches := resultRegex.FindStringSubmatch(line); len(matches) > 0 {
			res := &TestResult{
				Status:   matches[1],
				Protocol: matches[2],
				Scenario: strings.ReplaceAll(matches[3], "_", " "),
				Duration: matches[4],
			}
			results = append(results, res)
			
			if res.Status == "FAIL" {
				collectingFail = true
			}
			continue
		}

		// Print global level lines
		if !strings.HasPrefix(line, "PASS") && !strings.HasPrefix(line, "FAIL") && !strings.HasPrefix(line, "ok") && !strings.HasPrefix(line, "?") && !strings.HasPrefix(line, "=== RUN") && !strings.HasPrefix(line, "--- PASS: Test") && !strings.HasPrefix(line, "--- FAIL: Test") {
			if collectingFail {
				failedLogs = append(failedLogs, line)
			}
			fmt.Println(line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	// Print Summary Table
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🧪 PHOENIX FUNCTIONAL TEST RESULTS 🧪")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("%-20s | %-35s | %-10s | %-10s\n", "PROTOCOL", "SCENARIO", "STATUS", "DURATION")
	fmt.Println(strings.Repeat("-", 80))

	passed := 0
	failed := 0

	for _, res := range results {
		statusIcon := "✅ PASS"
		if res.Status == "FAIL" {
			statusIcon = "❌ FAIL"
			failed++
		} else if res.Status == "SKIP" {
			statusIcon = "⚠️ SKIP"
		} else {
			passed++
		}

		fmt.Printf("%-20s | %-35s | %-10s | %-10s\n", 
			res.Protocol, 
			res.Scenario, 
			statusIcon, 
			res.Duration,
		)
	}
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Total: %d | Passed: %d | Failed: %d\n", len(results), passed, failed)
	
	if failed > 0 {
		fmt.Println("\n❌ Test Suite Failed! Check logs above.")
		os.Exit(1)
	}
}
