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
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/pulumi/pulumi/pkg/v3/cloudsetup/awssetup"
	awssetuptypes "github.com/pulumi/pulumi/pkg/v3/cloudsetup/awssetup/types"
	cloudsetup "github.com/pulumi/pulumi/pkg/v3/cloudsetup/common"
	"github.com/pulumi/pulumi/pkg/v3/cmd/pulumi/ui"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
)

// awsPolicyARNs maps the --policy choice to the managed policy attached to the OIDC role.
// There is deliberately no default: full access is needed for Deployments and read-only
// for Insights, so the choice is not a matter of degree.
var awsPolicyARNs = map[string]string{
	"admin":    "arn:aws:iam::aws:policy/AdministratorAccess",
	"readonly": "arn:aws:iam::aws:policy/ReadOnlyAccess",
}

var awsResourceNames = map[string]string{
	awssetup.ResourceTypeAWSOIDCProvider:         "Identity Provider",
	awssetup.ResourceTypeAWSRole:                 "IAM Role",
	awssetup.ResourceTypeAWSRolePolicyAttachment: "IAM Role Policy Attachment",
}

// awsCredentialSource enumerates the AWS accounts a user can configure and builds a setup
// client for one of them.
//
// Device authorization discovers many accounts and mints per-account credentials from an
// access token. Existing credentials resolve to the single account they already belong to.
type awsCredentialSource interface {
	ListAccounts(ctx context.Context) ([]cloudsetup.CloudAccount, error)
	ClientFor(ctx context.Context, accountID, accountRoleName, oidcIssuer string) (awssetup.Client, error)
}

// ssoCredentialSource is an awsCredentialSource backed by an AWS SSO device authorization.
// It is the only source that can enumerate more than one account.
type ssoCredentialSource struct {
	client      awssetup.SSOClient
	accessToken string
}

func (s *ssoCredentialSource) ListAccounts(ctx context.Context) ([]cloudsetup.CloudAccount, error) {
	return s.client.ListAccounts(ctx, s.accessToken)
}

func (s *ssoCredentialSource) ClientFor(
	ctx context.Context, accountID, accountRoleName, oidcIssuer string,
) (awssetup.Client, error) {
	cfg, err := s.client.ExchangeCredentials(ctx, s.accessToken, accountID, accountRoleName)
	if err != nil {
		return nil, fmt.Errorf("obtaining credentials: %w", err)
	}
	return awssetup.NewClient(ctx, &cfg, oidcIssuer)
}

// ambientCredentialSource is an awsCredentialSource backed by the AWS SDK's default provider
// chain: environment variables, a shared-config profile (including one logged in with
// `aws sso login`), web identity, container credentials, or IMDS.
//
// It always resolves to exactly one account, so it cannot enumerate.
type ambientCredentialSource struct {
	cfg     aws.Config
	account cloudsetup.CloudAccount
	// origin names where the credentials came from, for display.
	origin string
}

// credentialSourceLabel turns an aws.Credentials.Source into something worth showing a user.
func credentialSourceLabel(source string) string {
	switch source {
	case "SSOProvider":
		return "AWS SSO"
	case "EnvConfigCredentials":
		return "environment variables"
	case "SharedConfigCredentials":
		return "shared config profile"
	case "AssumeRoleProvider":
		return "assumed role"
	case "EC2RoleProvider":
		return "EC2 instance role"
	case "EcsContainer":
		return "container credentials"
	case "ProcessProvider":
		return "credential_process"
	case "WebIdentityCredentials":
		return "web identity"
	case "":
		return "AWS credentials"
	default:
		return source
	}
}

// errNoAWSCredentials reports that the environment supplies no credentials at all, as opposed
// to supplying ones that do not work. Only the former is worth falling back to a browser for.
var errNoAWSCredentials = errors.New("no AWS credentials found")

// newAmbientCredentialSource resolves whatever credentials the environment already provides,
// and the account they belong to.
//
// It returns an error wrapping errNoAWSCredentials when there are none to use, and a plain
// error when credentials exist but AWS rejects them.
func newAmbientCredentialSource(ctx context.Context) (*ambientCredentialSource, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration: %w", err)
	}

	// LoadDefaultConfig is lazy: missing keys and expired SSO sessions only surface here.
	// Retrieve succeeding proves credentials were *found*, not that they work: it does no
	// validation, and will happily hand back a bogus key pair from the environment.
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoAWSCredentials, err)
	}

	// GetCallerIdentity is what proves the credentials work. Failing here is a real error --
	// a revoked session, a network problem, an SCP -- and must not be mistaken for "go and
	// authenticate", or a typo'd access key would silently open a browser.
	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("AWS rejected the credentials from %s: %w", credentialSourceLabel(creds.Source), err)
	}

	return &ambientCredentialSource{
		cfg:     cfg,
		account: cloudsetup.CloudAccount{ID: aws.ToString(identity.Account)},
		origin:  credentialSourceLabel(creds.Source),
	}, nil
}

func (a *ambientCredentialSource) ListAccounts(context.Context) ([]cloudsetup.CloudAccount, error) {
	return []cloudsetup.CloudAccount{a.account}, nil
}

func (a *ambientCredentialSource) ClientFor(
	_ context.Context, _, _, oidcIssuer string,
) (awssetup.Client, error) {
	return awssetup.NewClientFromConfig(a.cfg, oidcIssuer), nil
}

// newSSOCredentialSource runs the device authorization flow and blocks until it is approved.
func newSSOCredentialSource(
	ctx context.Context, esc *escCommand, startURL, region string,
) (*ssoCredentialSource, error) {
	client, err := awssetup.NewSSOClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("creating AWS SSO client: %w", err)
	}

	cfg, err := client.Initiate(ctx, startURL)
	if err != nil {
		return nil, fmt.Errorf("starting AWS SSO device authorization: %w", err)
	}

	fmt.Fprintf(esc.stdout, "\nConfirm the code %s to authorize this device:\n  %s\n\n",
		cfg.UserCode, cfg.VerificationURL)
	if err := browser.OpenURL(cfg.VerificationURL); err != nil {
		fmt.Fprintf(esc.stderr, "Could not open a browser automatically; visit the URL above.\n")
	}
	fmt.Fprintf(esc.stdout, "Waiting for authorization...\n")

	accessToken, err := pollForSSOAccessToken(ctx, client, cfg)
	if err != nil {
		return nil, err
	}
	return &ssoCredentialSource{client: client, accessToken: accessToken}, nil
}

// ssoSlowDownBackoff is added to the poll interval each time AWS asks us to slow down.
const ssoSlowDownBackoff = 5 * time.Second

// pollForSSOAccessToken polls until the device authorization is approved, or fails.
//
// The device code's own ExpiresIn bounds the wait rather than a fixed cap: the user has to
// switch to a browser and authenticate with their identity provider, which routinely takes
// longer than a minute.
func pollForSSOAccessToken(
	ctx context.Context, client awssetup.SSOClient, cfg *awssetuptypes.SSOConfig,
) (string, error) {
	deadline := time.Now().Add(time.Duration(cfg.ExpiresIn) * time.Second)

	interval := max(time.Duration(cfg.Interval)*time.Second, time.Second)

	for {
		accessToken, err := client.ExchangeAccessToken(ctx, cfg)
		if err == nil {
			return accessToken, nil
		}

		retry, err := classifySSOTokenError(err)
		if !retry {
			return "", err
		}

		var slowDown *ssooidctypes.SlowDownException
		if errors.As(err, &slowDown) {
			interval += ssoSlowDownBackoff
		}

		if time.Now().Add(interval).After(deadline) {
			return "", errors.New("timed out waiting for the authorization to be approved")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
}

// classifySSOTokenError decides whether a CreateToken failure is worth polling through,
// returning the error to surface when it is not.
//
// Per RFC 8628 the device flow continues only on `authorization_pending` and `slow_down`;
// every other OAuth error is final. Defaulting the other way means a user who declines the
// prompt watches the CLI poll until the device code expires. Note CreateToken also returns
// codes the SDK does not model (a declined prompt may surface as a generic `access_denied`
// rather than AccessDeniedException), so this keys off "is it an API error at all" rather
// than an allowlist of concrete types.
func classifySSOTokenError(err error) (retry bool, fatal error) {
	var pending *ssooidctypes.AuthorizationPendingException
	var slowDown *ssooidctypes.SlowDownException
	if errors.As(err, &pending) || errors.As(err, &slowDown) {
		return true, nil
	}

	var expired *ssooidctypes.ExpiredTokenException
	if errors.As(err, &expired) {
		return false, errors.New("the authorization request expired before it was approved")
	}

	var serverErr *ssooidctypes.InternalServerException
	if errors.As(err, &serverErr) {
		return true, nil
	}

	// Any other modelled or generic API error is a final answer from the service: the request
	// was denied, the device code is invalid, the client is unauthorized, and so on.
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if apiErr.ErrorCode() == "AccessDeniedException" || apiErr.ErrorCode() == "access_denied" {
			return false, errors.New("the authorization request was denied")
		}
		return false, fmt.Errorf("authorization failed: %w", err)
	}

	// Not an API error at all — a transport hiccup. Keep polling.
	return true, nil
}

// inferSSOSettings reads the start URL and region from the effective shared-config profile,
// so the device flow can run without flags when the machine already knows an SSO instance.
//
// Only the one profile the SDK would use is consulted; enumerating every profile would list
// the same SSO instance once per profile.
func inferSSOSettings(ctx context.Context) (startURL, region string) {
	envCfg, err := config.NewEnvConfig()
	if err != nil {
		return "", ""
	}
	profile := envCfg.SharedConfigProfile
	if profile == "" {
		profile = "default"
	}
	sc, err := config.LoadSharedConfigProfile(ctx, profile)
	if err != nil {
		return "", ""
	}
	if sc.SSOSession != nil {
		return sc.SSOSession.SSOStartURL, sc.SSOSession.SSORegion
	}
	return sc.SSOStartURL, sc.SSORegion
}

// newDeviceCredentialSource starts a device authorization, filling in the SSO instance from
// the shared config when it was not given on the command line.
func newDeviceCredentialSource(
	ctx context.Context, esc *escCommand, startURL, region string,
) (awsCredentialSource, error) {
	if startURL == "" || region == "" {
		inferredURL, inferredRegion := inferSSOSettings(ctx)
		if startURL == "" {
			startURL = inferredURL
		}
		if region == "" {
			region = inferredRegion
		}
	}
	if startURL == "" || region == "" {
		return nil, errors.New(
			"could not determine the AWS SSO instance; pass --sso-start-url and --sso-region")
	}
	return newSSOCredentialSource(ctx, esc, startURL, region)
}

// resolveAWSCredentialSource decides how to authenticate, offering the user a choice between
// the credentials they already have and a browser sign-in.
//
// The second return value reports whether the source can configure more than one account.
func resolveAWSCredentialSource(
	ctx context.Context, esc *escCommand, ssoStartURL, ssoRegion string, yes bool,
) (awsCredentialSource, bool, error) {
	// An explicit start URL means the user wants the browser flow.
	if ssoStartURL != "" {
		source, err := newDeviceCredentialSource(ctx, esc, ssoStartURL, ssoRegion)
		return source, true, err
	}

	ambient, ambientErr := newAmbientCredentialSource(ctx)
	if ambientErr != nil {
		// Credentials that exist but do not work are a problem to report, not a reason to
		// open a browser.
		if !errors.Is(ambientErr, errNoAWSCredentials) {
			return nil, false, ambientErr
		}
		fmt.Fprintf(esc.stdout, "No existing AWS credentials found; signing in with AWS SSO.\n")
		source, err := newDeviceCredentialSource(ctx, esc, ssoStartURL, ssoRegion)
		return source, true, err
	}

	existingLabel := fmt.Sprintf("Use existing AWS credentials - account %s (via %s) [single account]",
		ambient.account.ID, ambient.origin)
	deviceLabel := "Sign in with AWS SSO in your browser [multiple accounts]"

	if yes {
		fmt.Fprintf(esc.stdout, "Using AWS account %s (via %s).\n", ambient.account.ID, ambient.origin)
		return ambient, false, nil
	}

	choice := ui.PromptUser(
		"How would you like to authenticate to AWS?",
		[]string{existingLabel, deviceLabel}, existingLabel, esc.colors)
	switch choice {
	case existingLabel:
		return ambient, false, nil
	case deviceLabel:
		source, err := newDeviceCredentialSource(ctx, esc, ssoStartURL, ssoRegion)
		return source, true, err
	default:
		return nil, false, errors.New("cancelled")
	}
}

// selectedAWSAccount is an account the user chose, along with the SSO role to assume in it.
type selectedAWSAccount struct {
	account cloudsetup.CloudAccount
	// roleName is the SSO role used to *perform* the setup. It is unrelated to the OIDC
	// role the setup creates. Empty when credentials do not come from SSO.
	roleName string
}

// selectAWSAccounts resolves which accounts to configure and which SSO role to use in each.
func selectAWSAccounts(
	esc *escCommand, accounts []cloudsetup.CloudAccount, accountIDs []string, ssoRole string, yes bool,
) ([]selectedAWSAccount, error) {
	if len(accounts) == 0 {
		return nil, errors.New("no AWS accounts are accessible with these credentials")
	}

	chosen := accounts
	if len(accountIDs) > 0 {
		chosen = nil
		for _, id := range accountIDs {
			i := slices.IndexFunc(accounts, func(a cloudsetup.CloudAccount) bool { return a.ID == id })
			if i < 0 {
				return nil, fmt.Errorf("account %s is not accessible with these credentials", id)
			}
			chosen = append(chosen, accounts[i])
		}
	} else if len(accounts) > 1 {
		if yes {
			return nil, errors.New("multiple accounts are accessible; pass --account to choose without prompting")
		}
		labels := make([]string, len(accounts))
		for i, a := range accounts {
			labels[i] = fmt.Sprintf("%s (%s)", a.Name, a.ID)
		}
		picked := ui.PromptUserMulti("Which AWS accounts should be set up?", labels, nil, esc.colors)
		if len(picked) == 0 {
			return nil, errors.New("no accounts selected")
		}
		chosen = nil
		for _, label := range picked {
			i := slices.Index(labels, label)
			chosen = append(chosen, accounts[i])
		}
	}

	selected := make([]selectedAWSAccount, 0, len(chosen))
	for _, account := range chosen {
		role, err := selectAWSAccountRole(esc, account, ssoRole, yes)
		if err != nil {
			return nil, err
		}
		selected = append(selected, selectedAWSAccount{account: account, roleName: role})
	}
	return selected, nil
}

// selectAWSAccountRole picks the SSO role to assume in an account.
//
// The role must be able to create IAM resources. Picking a read-only role here surfaces as
// an AccessDenied several API calls later, so the chosen role is always echoed back.
func selectAWSAccountRole(
	esc *escCommand, account cloudsetup.CloudAccount, ssoRole string, yes bool,
) (string, error) {
	switch {
	case ssoRole != "":
		if !slices.Contains(account.Roles, ssoRole) {
			return "", fmt.Errorf("role %s is not available in account %s", ssoRole, account.ID)
		}
		return ssoRole, nil

	case len(account.Roles) == 0:
		return "", fmt.Errorf("no roles are available in account %s", account.ID)

	case len(account.Roles) == 1:
		fmt.Fprintf(esc.stdout, "Using role %s in account %s.\n", account.Roles[0], account.ID)
		return account.Roles[0], nil

	case yes:
		return "", fmt.Errorf(
			"account %s has multiple roles; pass --sso-role to choose without prompting", account.ID)

	default:
		msg := fmt.Sprintf("Which role should be used to set up account %s?", account.ID)
		role := ui.PromptUser(msg, account.Roles, account.Roles[0], esc.colors)
		if role == "" {
			return "", errors.New("no role selected")
		}
		return role, nil
	}
}

// setupAWSAccounts configures OIDC in each selected account, collecting per-account outcomes.
func setupAWSAccounts(
	ctx context.Context,
	esc *escCommand,
	source awsCredentialSource,
	selected []selectedAWSAccount,
	oidcIssuer, orgName, oidcRoleName, policyArn string,
) []accountSetupResult {
	results := make([]accountSetupResult, 0, len(selected))
	for _, sel := range selected {
		fmt.Fprintf(esc.stdout, "\nSetting up account %s...\n", sel.account.ID)

		client, err := source.ClientFor(ctx, sel.account.ID, sel.roleName, oidcIssuer)
		if err != nil {
			results = append(results, accountSetupResult{account: sel.account, err: err})
			continue
		}

		// Both a result and an error can come back: the result records which resources
		// were created before the failure.
		result, err := client.SetupOIDCInfrastructure(ctx, orgName, oidcRoleName, policyArn)
		results = append(results, accountSetupResult{account: sel.account, result: result, err: err})
	}
	return results
}

// awsRoleARN returns the ARN of the OIDC role created for an account.
func awsRoleARN(result *cloudsetup.CloudSetupResult) (string, bool) {
	if result == nil {
		return "", false
	}
	for _, res := range result.Resources {
		if res.Type == awssetup.ResourceTypeAWSRole && res.ID != "" {
			return res.ID, true
		}
	}
	return "", false
}

// awsEnvOptions configures the ESC environments written after setup succeeds.
type awsEnvOptions struct {
	// envRef names a single environment. Only valid when one account was set up.
	envRef string
	// projectName is the ESC project that per-account environments are created in.
	projectName string
	sessionName string
	duration    string
}

// sanitizeEnvName derives a default environment name from an AWS account name,
// matching the naming the Pulumi Cloud console uses.
func sanitizeEnvName(accountName, accountID string) string {
	base := accountName
	if base == "" {
		base = accountID
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.ToLower(b.String() + "-env")
}

// createAWSEnvironments writes an `fn::open::aws-login` OIDC block into one environment per
// successfully configured account, reusing the same helpers as `env provider aws-login oidc`.
//
// Only successful accounts get an environment: an environment pointing at a role that was
// never created would resolve to nothing at open time.
func createAWSEnvironments(
	ctx context.Context, setup *setupCommand, org string, results []accountSetupResult, opts awsEnvOptions,
) error {
	path, err := resource.ParsePropertyPath(awsLoginPath)
	if err != nil {
		return fmt.Errorf("invalid provider path %q: %w", awsLoginPath, err)
	}

	var attempted, failed int
	for _, r := range results {
		if !r.succeeded() {
			continue
		}
		attempted++

		roleArn, ok := awsRoleARN(r.result)
		if !ok {
			fmt.Fprintf(setup.esc().stderr, "%s: IAM role missing from the setup result\n", r.label())
			failed++
			continue
		}

		envName := opts.envRef
		if envName == "" {
			envName = fmt.Sprintf("%s/%s/%s", org, opts.projectName, sanitizeEnvName(r.account.Name, r.account.ID))
		}
		ref := setup.env.parseRef(envName)

		fmt.Fprintf(setup.esc().stdout, "\nConfiguring environment %s for account %s:\n", ref.String(), r.account.ID)

		node := buildAWSLoginOIDCNode(roleArn, opts.sessionName, opts.duration, nil, nil)
		if err := ensureProviderEnv(ctx, setup.env, ref, true); err != nil {
			fmt.Fprintf(setup.esc().stderr, "  %v\n", err)
			failed++
			continue
		}
		if err := applyProviderUpdate(ctx, setup.env, ref, "", path, node); err != nil {
			fmt.Fprintf(setup.esc().stderr, "  %v\n", err)
			failed++
			continue
		}
	}

	if attempted > 0 && failed == attempted {
		return errors.New("failed to create any environment")
	}
	return nil
}

// awsLoginPath is the property path under `values` where the login block is written,
// matching the default of `env provider aws-login`.
const awsLoginPath = "aws.login"

func newSetupAWSCmd(setup *setupCommand) *cobra.Command {
	var (
		ssoStartURL string
		ssoRegion   string
		ssoRole     string
		accountIDs  []string
		policy      string
		orgName     string
		yes         bool

		envRef      string
		projectName string
		sessionName string
		duration    string
	)

	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Set up AWS OIDC integration for Pulumi ESC",
		Long: "[EXPERIMENTAL] Set up AWS OIDC integration for Pulumi ESC\n" +
			"\n" +
			"Creates, in each selected AWS account:\n" +
			"  - an OIDC identity provider trusting Pulumi Cloud\n" +
			"  - an IAM role whose trust policy is scoped to your organization\n" +
			"  - an attachment of the chosen managed policy to that role\n" +
			"\n" +
			"You are asked how to authenticate: with the AWS credentials you already have, which\n" +
			"configures the single account they belong to, or by signing in to AWS SSO in your\n" +
			"browser, which lets you configure several accounts at once.\n" +
			"\n" +
			"Examples:\n" +
			"  pulumi env setup aws --policy admin\n" +
			"\n" +
			"  # Use existing credentials without prompting.\n" +
			"  pulumi env setup aws --policy readonly --yes\n" +
			"\n" +
			"  # Force the browser sign-in and configure one account non-interactively.\n" +
			"  pulumi env setup aws --sso-start-url https://my.awsapps.com/start \\\n" +
			"    --sso-region us-east-1 --policy readonly \\\n" +
			"    --account 123456789012 --sso-role AdministratorAccess --yes\n",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			esc := setup.esc()

			if err := esc.getCachedClient(ctx); err != nil {
				return err
			}

			oidcIssuer, err := setup.oidcIssuer()
			if err != nil {
				return err
			}
			org, err := setup.org(orgName)
			if err != nil {
				return err
			}

			policy, err = setup.resolvePolicy(policy, yes)
			if err != nil {
				return err
			}
			policyArn := awsPolicyARNs[policy]
			// The org and policy are encoded into the role name so that separate orgs, and
			// separate policies within an org, never collide on the same role and silently
			// inherit each other's trust policy.
			oidcRoleName := fmt.Sprintf("pulumi-esc-oidc-%s-%s-role", org, path.Base(policyArn))

			// Catch the flag conflict before the browser round-trip when the accounts are
			// named explicitly. The prompted case can only be checked after selection.
			if envRef != "" && len(accountIDs) > 1 {
				return errors.New("--environment cannot be used when setting up more than one account")
			}

			source, multiAccount, err := resolveAWSCredentialSource(ctx, esc, ssoStartURL, ssoRegion, yes)
			if err != nil {
				return err
			}

			accounts, err := source.ListAccounts(ctx)
			if err != nil {
				return fmt.Errorf("listing AWS accounts: %w", err)
			}

			var selected []selectedAWSAccount
			if multiAccount {
				selected, err = selectAWSAccounts(esc, accounts, accountIDs, ssoRole, yes)
				if err != nil {
					return err
				}
			} else {
				// Existing credentials belong to one account and carry no role to choose.
				if ssoRole != "" {
					return errors.New("--sso-role only applies to browser sign-in")
				}
				account := accounts[0]
				if len(accountIDs) > 1 || (len(accountIDs) == 1 && accountIDs[0] != account.ID) {
					return fmt.Errorf(
						"these credentials belong to account %s; --account cannot select a different one",
						account.ID)
				}
				selected = []selectedAWSAccount{{account: account}}
			}

			// One environment name cannot name several environments. Fail before creating any
			// IAM roles we would then be unable to reference.
			if envRef != "" && len(selected) > 1 {
				return errors.New("--environment cannot be used when setting up more than one account")
			}

			fmt.Fprintf(esc.stdout, "\nAbout to configure OIDC for organization %s:\n", org)
			for _, sel := range selected {
				fmt.Fprintf(esc.stdout, "  account %s: create role %s with %s\n",
					sel.account.ID, oidcRoleName, policyArn)
			}
			// Gate on `yes` rather than using PromptUserSkippable, which returns the default
			// option when skipping: the interactive default must stay "no" for a prompt that
			// creates an admin-scoped IAM role.
			if !yes {
				if ui.PromptUser("Proceed?", []string{"yes", "no"}, "no", esc.colors) != "yes" {
					return errors.New("cancelled")
				}
			}

			setup.printHeading("Setting up Infrastructure")
			results := setupAWSAccounts(ctx, esc, source, selected, oidcIssuer, org, oidcRoleName, policyArn)
			renderSetupResults(esc.stdout, results, awsResourceNames)

			if !slices.ContainsFunc(results, accountSetupResult.succeeded) {
				return errors.New("failed to configure OIDC in any account")
			}

			setup.printHeading("Setting up Environment(s)")
			return createAWSEnvironments(ctx, setup, org, results, awsEnvOptions{
				envRef:      envRef,
				projectName: projectName,
				sessionName: sessionName,
				duration:    duration,
			})
		},
	}

	cmd.Flags().StringVar(&ssoStartURL, "sso-start-url", "",
		"the AWS SSO start URL; forces the browser sign-in (inferred from your AWS config when omitted)")
	cmd.Flags().StringVar(&ssoRegion, "sso-region", "",
		"the region the AWS SSO instance is hosted in (inferred from your AWS config when omitted)")
	cmd.Flags().StringVar(&ssoRole, "sso-role", "",
		"the SSO role to assume when setting up each account (prompted for when ambiguous)")
	cmd.Flags().StringArrayVar(&accountIDs, "account", nil,
		"an AWS account to set up (repeatable; prompted for when omitted)")
	cmd.Flags().StringVar(&policy, "policy", "",
		"the access level for the OIDC role: admin (required for Deployments) or readonly "+
			"(required for Insights); prompted for when omitted")
	cmd.Flags().StringVar(&orgName, "org", "", "the Pulumi organization to configure OIDC for")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip all confirmation prompts")

	cmd.Flags().StringVar(&envRef, "environment", "",
		"[<org>/][<project>/]<environment-name> to write; only valid for a single account")
	cmd.Flags().StringVar(&projectName, "project", "aws-login",
		"the ESC project that per-account environments are created in")
	cmd.Flags().StringVar(&sessionName, "session-name", "pulumi-environments-session",
		"the AWS session name recorded for the assumed role")
	cmd.Flags().StringVar(&duration, "duration", "1h", "the session duration for the assumed role")

	return cmd
}
