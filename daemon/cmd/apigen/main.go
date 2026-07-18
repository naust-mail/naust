// apigen writes the TypeScript wire-contract types generated from the
// internal/api package. Run via go generate ./internal/api; the drift
// test in internal/apigen fails when the output is stale.
package main

import (
	"flag"
	"log"
	"os"

	"naust/daemon/internal/apigen"
)

func main() {
	pkgDir := flag.String("pkg", ".", "directory of the Go api package")
	out := flag.String("out", "", "path of the TypeScript file to write")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	src, err := apigen.Generate(*pkgDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		log.Fatal(err)
	}
}
