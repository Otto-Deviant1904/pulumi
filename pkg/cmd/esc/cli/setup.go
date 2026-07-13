// Copyright 2026, Pulumi Corporation.
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

package cli

import (
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/spf13/cobra"

	cloudsetup "github.com/pulumi/pulumi/pkg/v3/cloudsetup/common"
	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/ui"
	"github.com/pulumi/pulumi/sdk/v3/go/common/diag/colors"
)

type setupCommand struct {
	// env is held rather than escCommand so that setup can reuse the provider
	// helpers (ensureProviderEnv, applyProviderUpdate) to write the login block.
	env *envCommand
}

func newSetupCmd(env *envCommand) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up cloud provider OIDC integrations",
		Long: "[EXPERIMENTAL] Set up cloud provider OIDC integrations\n" +
			"\n" +
			"Creates the identity resources a cloud provider needs in order to trust Pulumi\n" +
			"Cloud as an OIDC identity provider, so that environments can obtain short-lived\n" +
			"credentials without any long-lived secrets.\n",
		Args: cobra.NoArgs,
	}

	setup := &setupCommand{env: env}

	cmd.AddCommand(newSetupAWSCmd(setup))
	cmd.AddCommand(newSetupAzureCmd(setup))
	cmd.AddCommand(newSetupGCPCmd(setup))

	return cmd
}

// esc returns the underlying esc command, for stdout/stderr and the API client.
func (s *setupCommand) esc() *escCommand {
	return s.env.esc
}

// printHeading writes a colorized section heading to stdout, preceded by a blank line.
func (s *setupCommand) printHeading(title string) {
	esc := s.esc()
	fmt.Fprintln(esc.stdout)
	fmt.Fprintln(esc.stdout, esc.colors.Colorize(colors.SpecHeadline+title+colors.Reset))
}

// oidcIssuer returns the OIDC issuer URL of the currently logged-in backend.
//
// The issuer is scheme://host/oidc, matching how pulumi-service derives it from its API domain.
// Any path on the account's backend URL (e.g. the org login in a self-hosted URL) is dropped:
// the issuer is a property of the service, not the org.
//
// getCachedClient has already rejected DIY backends via checkBackendURL by this point.
func (s *setupCommand) oidcIssuer() (string, error) {
	backendURL := s.esc().account.BackendURL
	if backendURL == "" {
		return "", errors.New("could not determine the current backend; run `pulumi login`")
	}
	parsed, err := url.Parse(backendURL)
	if err != nil {
		return "", fmt.Errorf("parsing backend URL %q: %w", backendURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("backend URL %q is not an absolute URL", backendURL)
	}
	return parsed.Scheme + "://" + parsed.Host + "/oidc", nil
}

// org returns the Pulumi organization to configure OIDC for, preferring an explicit flag.
func (s *setupCommand) org(orgFlag string) (string, error) {
	if orgFlag != "" {
		return orgFlag, nil
	}
	if s.esc().account.DefaultOrg != "" {
		return s.esc().account.DefaultOrg, nil
	}
	return "", errors.New("could not determine the organization; pass --org or set a default organization")
}

// Policy prompt labels. The returned choice is mapped back to the `admin`/`readonly` key each
// provider looks up in its own policy map.
const (
	policyAdminLabel    = "admin - full access (required for Deployments)"
	policyReadonlyLabel = "readonly - read-only access (required for Insights)"
)

// resolvePolicy returns the `admin`/`readonly` access level, prompting when --policy was omitted.
//
// There is deliberately no default: admin is needed for Deployments and readonly for Insights, so
// the choice is not a matter of degree and must be made explicitly. With --yes there is nobody to
// prompt, so an omitted policy is an error rather than a silent default.
func (s *setupCommand) resolvePolicy(policy string, yes bool) (string, error) {
	switch policy {
	case "admin", "readonly":
		return policy, nil
	case "":
		// prompt below
	default:
		return "", fmt.Errorf("--policy must be one of `admin` or `readonly`, got %q", policy)
	}

	if yes {
		return "", errors.New("--policy must be set when using --yes; pass admin or readonly")
	}

	switch ui.PromptUser("What level of access should the OIDC identity have?",
		[]string{policyAdminLabel, policyReadonlyLabel}, policyAdminLabel, s.esc().colors) {
	case policyAdminLabel:
		return "admin", nil
	case policyReadonlyLabel:
		return "readonly", nil
	default:
		return "", errors.New("no policy selected")
	}
}

// accountSetupResult pairs a cloud account with the outcome of setting it up.
//
// Setup is reported per account rather than as a single boolean because it can partially
// succeed: SetupOIDCInfrastructure may create some resources, fail on a later one, and
// return both a non-nil result and a non-nil error.
type accountSetupResult struct {
	account cloudsetup.CloudAccount
	result  *cloudsetup.CloudSetupResult
	err     error
}

// succeeded reports whether every resource for this account was created or already existed.
func (r accountSetupResult) succeeded() bool {
	return r.err == nil && r.result != nil && r.result.Success
}

// label returns a human-readable identifier for the account.
func (r accountSetupResult) label() string {
	switch {
	case r.account.Name != "" && r.account.ID != "":
		return fmt.Sprintf("%s (%s)", r.account.Name, r.account.ID)
	case r.account.Name != "":
		return r.account.Name
	default:
		return r.account.ID
	}
}

// renderSetupResults writes a per-account summary of what was created, existed, or failed.
// resourceNames maps provider-specific resource types to display names.
func renderSetupResults(w io.Writer, results []accountSetupResult, resourceNames map[string]string) {
	for _, r := range results {
		fmt.Fprintln(w)

		if r.result == nil {
			fmt.Fprintf(w, "%s: failed: %v\n", r.label(), r.err)
			continue
		}

		status := "done"
		if !r.result.Success {
			status = "incomplete"
		}
		fmt.Fprintf(w, "%s: %s\n", r.label(), status)

		for _, res := range r.result.Resources {
			name, ok := resourceNames[res.Type]
			if !ok {
				name = res.Type
			}
			fmt.Fprintf(w, "  %-32s %s", name, res.Status)
			switch {
			case res.Error != "":
				fmt.Fprintf(w, ": %s", res.Error)
			case res.ID != "":
				fmt.Fprintf(w, "  %s", res.ID)
			}
			fmt.Fprintln(w)
		}

		if r.result.Message != "" {
			fmt.Fprintf(w, "  %s\n", r.result.Message)
		}
		if r.err != nil {
			fmt.Fprintf(w, "  %v\n", r.err)
		}
	}
}
