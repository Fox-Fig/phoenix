package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func main() {
	mode := flag.String("mode", "test", "Mode: test or speedtest")
	flag.Parse()

	fmt.Println("==================================================")
	fmt.Printf(" Phoenix Interactive %s Runner\n", strings.Title(*mode))
	fmt.Println("==================================================")
	fmt.Println("Please select the type of test to run:")
	fmt.Println("  1) Modular Test   (Fast, In-Memory, Skips TOML parsing)")
	fmt.Println("  2) Real Simulator (E2E Black-box, Binary Execution, Real SOCKS5)")
	fmt.Print("\nEnter choice (1 or 2): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var cmd *exec.Cmd
	if choice == "1" {
		fmt.Println("\nRunning Modular Tests...")
		if *mode == "test" {
			cmd1 := exec.Command("go", "test", "-v", "./pkg/testutils/...", "./pkg/transport/...")
			cmd2 := exec.Command("./bin/test-parser")
			runPiped(cmd1, cmd2)
			return
		} else {
			cmd1 := exec.Command("go", "test", "-v", "-bench", ".", "./pkg/transport/...")
			cmd2 := exec.Command("./bin/speedtest-parser")
			runPiped(cmd1, cmd2)
			return
		}
	} else if choice == "2" {
		fmt.Println("\nRunning E2E Real Simulation Tests...")
		if *mode == "test" {
			cmd1 := exec.Command("go", "test", "-v", "-run", "_E2E", "./pkg/transport/...")
			cmd2 := exec.Command("./bin/test-parser")
			runPiped(cmd1, cmd2)
			return
		} else {
			cmd1 := exec.Command("go", "test", "-v", "-bench", "_E2E", "-run", "^$", "./pkg/transport/...")
			cmd2 := exec.Command("./bin/speedtest-parser")
			runPiped(cmd1, cmd2)
			return
		}
	} else {
		fmt.Println("Invalid choice. Exiting.")
		os.Exit(1)
	}

	if cmd != nil {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			fmt.Printf("Test failed: %v\n", err)
			os.Exit(1)
		}
	}
}

func runPiped(cmd1, cmd2 *exec.Cmd) {
	r, w := io.Pipe()
	cmd1.Stdout = w
	cmd1.Stderr = os.Stderr
	cmd2.Stdin = r
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr

	if err := cmd1.Start(); err != nil {
		fmt.Printf("Error starting cmd1: %v\n", err)
		os.Exit(1)
	}
	if err := cmd2.Start(); err != nil {
		fmt.Printf("Error starting cmd2: %v\n", err)
		os.Exit(1)
	}

	go func() {
		cmd1.Wait()
		w.Close()
	}()

	err := cmd2.Wait()
	if err != nil {
		os.Exit(1)
	}
}
