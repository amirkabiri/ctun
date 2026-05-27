// Package transports implements the `ctun transports` subcommand, which prints
// the names of all transports that are registered in this build of the binary.
//
// The set of available transports is fixed at compile time: each transport
// sub-package's init() calls transport.Register, so a transport is included
// only if some translation unit imports it (directly or transitively). This
// command's blank import of internal/transport/syntfo below ensures the
// shipped syn-tfo transport is always represented; additional transports can
// be made visible by recompiling with extra `import _ "path/to/transport"`
// lines in this file (or anywhere else linked into the binary).
package transports

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"ctun/internal/transport"
	_ "ctun/internal/transport/syntfo" // register the "syn-tfo" transport

	"github.com/spf13/cobra"
)

var jsonOut bool

func init() {
	Cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the transport list as a JSON array of strings instead of one name per line.")
}

// Cmd is the cobra command for `ctun transports`.
var Cmd = &cobra.Command{
	Use:   "transports",
	Short: "List the transports compiled into this binary.",
	Long: `Prints the names of every transport registered in this build, one per line, sorted and lower-case.

The set of transports is fixed at compile time. Additional transports can be made available by recompiling with extra ` + "`import _ \"path/to/your/transport\"`" + ` lines so their init() functions run and register them.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTransports(os.Stdout, jsonOut)
	},
}

// runTransports writes the list of registered transports to out. When jsonOut
// is true the output is a JSON array of strings (compact, single line); when
// false it is one name per line. The data source is transport.Names(), which
// already returns its result sorted and lower-case.
func runTransports(out io.Writer, jsonOut bool) error {
	names := transport.Names()

	if jsonOut {
		// Compact, single-line JSON: tests and grep-style consumers prefer a
		// predictable one-line shape, and the array is short enough that
		// pretty-printing buys nothing.
		buf, err := json.Marshal(names)
		if err != nil {
			return fmt.Errorf("marshal transports: %w", err)
		}
		if _, err := fmt.Fprintf(out, "%s\n", buf); err != nil {
			return err
		}
		return nil
	}

	for _, n := range names {
		if _, err := fmt.Fprintln(out, n); err != nil {
			return err
		}
	}
	return nil
}
