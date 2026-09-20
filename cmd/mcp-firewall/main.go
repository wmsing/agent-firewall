package main

import (
	"github.com/wmsing/agent-firewall/eval"
	"log"
	"os"
)

func main() {
	log.SetOutput(os.Stderr)
	runMCP(os.Stdin, os.Stdout, eval.NewRiskEvaluator())
}
