// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build corpushelper

// Helper for hand-seeding canonical fixture files. Reads inputs from
// stdin (one per line, may be preceded by comments and blank lines),
// computes mask.Apply(rule, input), and writes `input<TAB>expected`
// lines to stdout. Comments and blanks pass through verbatim.
//
//	echo -e "a@b.com\nfoo@example.com" | \
//	  go run -tags corpushelper ./tests/corpus/_tools/expect email_address
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/axonops/mask"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: expect <rule>")
		os.Exit(2)
	}
	rule := os.Args[1]
	if !mask.HasRule(rule) {
		fmt.Fprintf(os.Stderr, "rule %q is not registered\n", rule)
		os.Exit(2)
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			fmt.Println(line)
			continue
		}
		input := line
		if i := strings.IndexByte(line, '\t'); i >= 0 {
			input = line[:i]
		}
		fmt.Printf("%s\t%s\n", input, mask.Apply(rule, input))
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
