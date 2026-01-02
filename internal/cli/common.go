package cli

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vasudevchavan/k8s-get-access-level/pkg/access"
	"github.com/vasudevchavan/k8s-get-access-level/pkg/client"
	"github.com/vasudevchavan/k8s-get-access-level/pkg/discovery"
)

type AccessOptions struct {
	UserNamespace string
	ClusterScope  bool
	Resource      string
}

func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("namespace", "n", "default", "Namespace Scope")
	cmd.Flags().String("resource", "", "Kubernetes resource")
	cmd.Flags().BoolP("clusterscope", "c", false, "Cluster Scope")
}

func ValidateCommonFlags(cmd *cobra.Command, args []string) (AccessOptions, error) {
	opts := AccessOptions{}
	var err error

	opts.UserNamespace, err = cmd.Flags().GetString("namespace")
	if err != nil {
		return opts, err
	}
	opts.Resource, err = cmd.Flags().GetString("resource")
	if err != nil {
		return opts, err
	}
	opts.ClusterScope, err = cmd.Flags().GetBool("clusterscope")
	if err != nil {
		return opts, err
	}

	clientset, err := client.GetClientset()
	if err != nil {
		return opts, err
	}

	// If a resource is specified, validate cluster vs namespace
	if opts.Resource != "" {
		resolved, err := discovery.ResolveResourceName(clientset.Discovery(), opts.Resource)
		if err != nil {
			return opts, err
		}
		opts.Resource = resolved

		resolver, err := discovery.NewResourceScopeResolver(clientset.Discovery())
		if err != nil {
			return opts, err
		}

		namespaced, err := resolver.IsNamespaced(opts.Resource)
		if err != nil {
			return opts, err
		}

		nsFlag := cmd.Flags().Changed("namespace")
		csFlag := cmd.Flags().Changed("clusterscope")

		//  user passed --namespace for cluster-scoped resource
		if !namespaced && nsFlag {
			return opts, fmt.Errorf("resource %q is cluster-scoped; --namespace is not allowed", opts.Resource)
		}

		//  user passed --clusterscope for namespaced resource
		if namespaced && csFlag && opts.ClusterScope {
			return opts, fmt.Errorf("resource %q is namespaced; --clusterscope is not allowed", opts.Resource)
		}

		//  set clusterScope automatically for cluster resources
		if !namespaced {
			opts.ClusterScope = true
			opts.UserNamespace = ""
		}

		//  set default namespace for namespaced resources if not specified
		if namespaced && !nsFlag {
			// This might be redundant as flag default is "default", but keeping logic
			opts.UserNamespace = "default"
		}
	}

	return opts, nil
}

func RunAccessCheck(cmd *cobra.Command, args []string, isServiceAccount bool, opts AccessOptions) error {
	username := args[0]
	displayUsername := username
	if isServiceAccount {
		// If namespace is not provided for SA, assume default or use the one set in flags
		saNamespace := opts.UserNamespace
		if saNamespace == "" {
			saNamespace = "default"
		}
		// Construct the full service account name: system:serviceaccount:<ns>:<name>
		if !strings.HasPrefix(username, "system:serviceaccount:") {
			username = fmt.Sprintf("system:serviceaccount:%s:%s", saNamespace, username)
		}
		displayUsername = username
	}

	clientset, err := client.GetClientset()
	if err != nil {
		return fmt.Errorf("error creating clientset: %v", err)
	}

	resolver, err := discovery.NewResourceScopeResolver(clientset.Discovery())
	if err != nil {
		return fmt.Errorf("error creating resolver: %v", err)
	}

	// Load rest config once
	restCfg, err := client.GetRestConfig()
	if err != nil {
		return fmt.Errorf("error loading rest config: %v", err)
	}

	// Create impersonated client once
	// We only include system:authenticated by default.
	groups := []string{"system:authenticated"}
	if isServiceAccount {
		groups = append(groups, "system:serviceaccounts")
		if opts.UserNamespace != "" {
			groups = append(groups, fmt.Sprintf("system:serviceaccounts:%s", opts.UserNamespace))
		}
	}

	impClient, err := access.NewImpersonatedClient(restCfg, username, groups)
	if err != nil {
		return fmt.Errorf("error creating impersonated client: %v", err)
	}

	var resourcesToCheck []string
	if opts.Resource != "" {
		resourcesToCheck = []string{opts.Resource}
	} else {
		resourcesToCheck, err = discovery.GetAllResources(clientset.Discovery())
		if err != nil {
			return fmt.Errorf("error fetching resources: %v", err)
		}
	}

	for _, res := range resourcesToCheck {
		// Skip subresources
		if strings.Contains(res, "/") {
			continue
		}

		namespaced, err := resolver.IsNamespaced(res)
		if err != nil {
			slog.Warn("Skipping resource", "resource", res, "error", err)
			continue
		}

		// Respect --clusterscope
		if opts.ClusterScope && namespaced {
			continue
		}
		if !opts.ClusterScope && !namespaced {
			continue
		}

		ns := ""
		if namespaced {
			ns = opts.UserNamespace
			if isServiceAccount {
				slog.Info("Inspecting access",
					"service_account", displayUsername,
					"resource", res,
					"namespace", ns,
				)
			} else {
				slog.Info("Inspecting access",
					"user", displayUsername,
					"resource", res,
					"namespace", ns,
				)
			}
		} else {
			if isServiceAccount {
				slog.Info("Inspecting access",
					"service_account", displayUsername,
					"resource", res,
					"scope", "cluster",
				)
			} else {
				slog.Info("Inspecting access",
					"user", displayUsername,
					"resource", res,
					"scope", "cluster",
				)
			}
		}

		checker := access.NewKubeChecker(impClient)
		accessMap, err := checker.Check(
			cmd.Context(),
			res,
			ns,
		)
		if err != nil {
			slog.Error("Error checking access", "error", err)
			continue
		}

		for verb, allowed := range accessMap {
			fmt.Printf("  %-6s : %v\n", verb, allowed)
		}
	}
	return nil
}
