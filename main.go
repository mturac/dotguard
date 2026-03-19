package main

import (
	"flag"
	"fmt"
	"os"
)

var Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "init":
		cmdInit()
	case "hook":
		if len(os.Args) < 3 {
			fmt.Println("Usage: dotguard hook [install|uninstall]")
			os.Exit(1)
		}
		cmdHook(os.Args[2])
	case "ci":
		cmdCI(os.Args[2:])
	case "version":
		fmt.Printf("dotguard v%s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := fs.String("config", ".dotguard.json", "Path to config file")
	ai := fs.Bool("ai", false, "Enable AI-powered analysis")
	verbose := fs.Bool("verbose", false, "Verbose output")
	staged := fs.Bool("staged", false, "Only scan git staged files")
	fs.Parse(args)

	cfg := LoadConfig(*configPath)
	scanPath := "."
	if fs.NArg() > 0 {
		scanPath = fs.Arg(0)
	}

	scanner := NewScanner(cfg, *verbose)
	var findings []Finding

	if *staged {
		files, err := GitStagedFiles()
		if err != nil {
			fmt.Printf("%s Could not get staged files: %v\n", colorRed("✗"), err)
			os.Exit(1)
		}
		findings = scanner.ScanFiles(files)
	} else {
		findings = scanner.ScanPath(scanPath)
	}

	if *ai && len(findings) > 0 {
		findings = AnalyzeWithAI(cfg, findings)
	}

	PrintFindings(findings, *verbose)

	if len(findings) > 0 {
		fmt.Printf("\n%s Found %d potential secret(s)\n", colorRed("✗"), len(findings))
		os.Exit(1)
	}

	fmt.Printf("\n%s No secrets found\n", colorGreen("✓"))
}

func cmdInit() {
	if _, err := os.Stat(".dotguard.json"); err == nil {
		fmt.Printf("%s .dotguard.json already exists\n", colorYellow("!"))
		return
	}

	err := os.WriteFile(".dotguard.json", []byte(DefaultConfig), 0644)
	if err != nil {
		fmt.Printf("%s Failed to create config: %v\n", colorRed("✗"), err)
		os.Exit(1)
	}

	fmt.Printf("%s Created .dotguard.json\n", colorGreen("✓"))
	fmt.Println("  Edit the file to customize scan rules and allowlist.")
}

func cmdHook(action string) {
	switch action {
	case "install":
		err := InstallHook()
		if err != nil {
			fmt.Printf("%s Failed to install hook: %v\n", colorRed("✗"), err)
			os.Exit(1)
		}
		fmt.Printf("%s Pre-commit hook installed\n", colorGreen("✓"))
	case "uninstall":
		err := UninstallHook()
		if err != nil {
			fmt.Printf("%s Failed to uninstall hook: %v\n", colorRed("✗"), err)
			os.Exit(1)
		}
		fmt.Printf("%s Pre-commit hook removed\n", colorGreen("✓"))
	default:
		fmt.Printf("Unknown hook action: %s\n", action)
		fmt.Println("Usage: dotguard hook [install|uninstall]")
		os.Exit(1)
	}
}

func cmdCI(args []string) {
	fs := flag.NewFlagSet("ci", flag.ExitOnError)
	configPath := fs.String("config", ".dotguard.json", "Path to config file")
	jsonOut := fs.Bool("json", false, "Output results as JSON")
	ai := fs.Bool("ai", false, "Enable AI-powered analysis")
	notify := fs.Bool("notify", false, "Send webhook notifications on findings")
	fs.Parse(args)

	cfg := LoadConfig(*configPath)
	scanner := NewScanner(cfg, false)
	findings := scanner.ScanPath(".")

	if *ai && len(findings) > 0 {
		findings = AnalyzeWithAI(cfg, findings)
	}

	if *jsonOut {
		PrintFindingsJSON(findings)
	} else {
		PrintFindings(findings, false)
	}

	if *notify && len(findings) > 0 {
		NotifyWebhooks(cfg, findings)
	}

	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "dotguard: found %d potential secret(s)\n", len(findings))
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`dotguard v%s — Catch secrets before they leak

Usage:
  dotguard <command> [options]

Commands:
  scan [path]       Scan files for secrets (default: current directory)
  init              Create .dotguard.json config file
  hook install      Install git pre-commit hook
  hook uninstall    Remove git pre-commit hook
  ci                CI/CD mode with exit codes
  version           Print version

Scan Options:
  -config string    Path to config file (default ".dotguard.json")
  -ai               Enable AI-powered secret analysis
  -verbose          Show detailed output
  -staged           Only scan git staged files

CI Options:
  -config string    Path to config file (default ".dotguard.json")
  -json             Output results as JSON
  -ai               Enable AI-powered secret analysis
  -notify           Send webhook notifications on findings

Examples:
  dotguard scan                     Scan current directory
  dotguard scan -staged             Scan only staged files
  dotguard scan -ai ./src           Scan with AI analysis
  dotguard ci -json -notify         CI mode with JSON + webhooks
  dotguard hook install             Set up pre-commit hook

`, Version)
}
