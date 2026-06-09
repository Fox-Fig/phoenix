package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type ScenarioResult struct {
	Protocol string
	Scenario string
	Latency  float64 // ms
	Upload   float64 // MB/s
	Download float64 // MB/s
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	
	// Regex matches: Benchmark<Protocol>/<Scenario>_<Metric>-<Threads>   <Iter>   <ns/op> ns/op   [<MB/s> MB/s]
	benchRegex := regexp.MustCompile(`^Benchmark(\w+)/(.+?)_(Latency|Upload|Download)(?:-\d+)?\s+\d+\s+([\d\.]+)\s+ns/op(?:\s+([\d\.]+)\s+MB/s)?`)

	results := make(map[string]*ScenarioResult)
	var orderedKeys []string

	fmt.Println("Running Benchmarks... (This may take a few minutes)")
	fmt.Println(strings.Repeat("=", 80))

	for scanner.Scan() {
		line := scanner.Text()
		
		// Print lines that are not benchmark data so the user can see progress and logs
		if !strings.HasPrefix(line, "Benchmark") {
			if !strings.HasPrefix(line, "PASS") && !strings.HasPrefix(line, "ok") && !strings.HasPrefix(line, "FAIL") {
				// To keep the output clean, we might just print errors or just ignore verbose logs
				// But let's print them so we don't hide panics or progress
				fmt.Println(line)
			}
			continue
		}

		matches := benchRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}

		protocol := matches[1]
		scenario := strings.ReplaceAll(matches[2], "_", " ")
		metric := matches[3]
		nsOpStr := matches[4]
		
		mbpsStr := ""
		if len(matches) >= 6 {
			mbpsStr = matches[5]
		}

		key := protocol + "|" + scenario
		
		res, exists := results[key]
		if !exists {
			res = &ScenarioResult{
				Protocol: protocol,
				Scenario: scenario,
			}
			results[key] = res
			orderedKeys = append(orderedKeys, key)
		}

		nsOp, _ := strconv.ParseFloat(nsOpStr, 64)
		mbps, _ := strconv.ParseFloat(mbpsStr, 64)

		switch metric {
		case "Latency":
			res.Latency = nsOp / 1000000.0 // convert ns to ms
		case "Upload":
			res.Upload = mbps
		case "Download":
			res.Download = mbps
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}

	// Print Summary Table
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🚀 PHOENIX TRANSPORT BENCHMARK RESULTS 🚀")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("%-20s | %-30s | %-10s | %-10s | %-10s\n", "PROTOCOL", "SCENARIO", "LATENCY", "UPLOAD", "DOWNLOAD")
	fmt.Println(strings.Repeat("-", 80))

	for _, key := range orderedKeys {
		res := results[key]
		
		latStr := fmt.Sprintf("%.2f ms", res.Latency)
		upStr := fmt.Sprintf("%.2f MB/s", res.Upload)
		dnStr := fmt.Sprintf("%.2f MB/s", res.Download)

		if res.Latency == 0 { latStr = "FAILED" }
		if res.Upload == 0 { upStr = "FAILED" }
		if res.Download == 0 { dnStr = "FAILED" }

		fmt.Printf("%-20s | %-30s | %-10s | %-10s | %-10s\n", 
			res.Protocol, 
			res.Scenario, 
			latStr, 
			upStr, 
			dnStr,
		)
	}
	fmt.Println(strings.Repeat("=", 80))
}
