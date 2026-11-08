package cli

import (
	"os"
	"time"

	"github.com/cenab/cinderlock/internal/endpointprobe"
	"github.com/cenab/cinderlock/internal/spec"
	"github.com/spf13/cobra"
)

func addEndpointProbe(helper *cobra.Command, o *options) {
	var target, method string
	var expected int
	var timeout int64
	var ca, authorization, allowHTTP bool
	command := &cobra.Command{Use: "endpoint-probe", Short: "Observe one declared endpoint from this worker's network context", Args: func(_ *cobra.Command, args []string) error {
		if len(args) != 0 {
			return spec.Err(2, "endpoint worker accepts no positional arguments")
		}
		return nil
	}, RunE: func(c *cobra.Command, _ []string) error {
		if timeout < 1 || timeout > spec.EndpointMaxTimeoutSeconds {
			return spec.Err(2, "endpoint timeout is outside the supported range")
		}
		opts := endpointprobe.Options{URL: target, Method: method, ExpectedStatus: expected, Timeout: time.Duration(timeout) * time.Second, AllowHTTP: allowHTTP}
		if ca {
			value, present := os.LookupEnv(endpointprobe.CAEnvironment)
			if !present || value == "" || len(value) > endpointprobe.MaxCABytes {
				return spec.Err(2, "endpoint CA environment material is missing or exceeds the supported limit")
			}
			opts.CAPEM = []byte(value)
		}
		if authorization {
			value, present := os.LookupEnv(endpointprobe.AuthorizationEnvironment)
			if !present || value == "" || len(value) > endpointprobe.MaxAuthorizationBytes {
				return spec.Err(2, "endpoint authorization environment material is missing or exceeds the supported limit")
			}
			opts.Authorization = value
		}
		ctx, cancel := o.context(c)
		defer cancel()
		result, err := endpointprobe.Run(ctx, opts)
		if result.Response == "observed" {
			if emitErr := o.emit(result); emitErr != nil {
				return emitErr
			}
		}
		return err
	}}
	command.SetFlagErrorFunc(func(_ *cobra.Command, _ error) error { return spec.Err(2, "invalid endpoint worker options") })
	command.Flags().StringVar(&target, "url", "", "Declared endpoint URL without credentials, query, or fragment")
	command.Flags().StringVar(&method, "method", "GET", "GET or HEAD")
	command.Flags().IntVar(&expected, "expected-status", 200, "Exact expected nonredirect response status")
	command.Flags().Int64Var(&timeout, "timeout-seconds", spec.EndpointDefaultTimeoutSeconds, "Bounded request wait, up to 120 seconds")
	command.Flags().BoolVar(&ca, "ca", false, "Use the fixed endpoint CA environment input")
	command.Flags().BoolVar(&authorization, "authorization", false, "Supply the fixed endpoint Authorization environment input")
	command.Flags().BoolVar(&allowHTTP, "allow-http", false, "Explicitly accept HTTP without CA or authorization material")
	_ = command.MarkFlagRequired("url")
	helper.AddCommand(command)
}
