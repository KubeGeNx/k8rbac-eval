package access

import (
	"context"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Checker checks access level for a resource.
type Checker interface {
	Check(ctx context.Context, resource, namespace string) (map[string]bool, error)
}

// KubeChecker implements Checker using a Kubernetes client.
type KubeChecker struct {
	Client kubernetes.Interface
}

// NewKubeChecker creates a new KubeChecker.
func NewKubeChecker(client kubernetes.Interface) *KubeChecker {
	return &KubeChecker{Client: client}
}

func NewImpersonatedClient(
	restConfig *rest.Config,
	username string,
	groups []string,
) (kubernetes.Interface, error) {

	cfg := rest.CopyConfig(restConfig)
	cfg.Impersonate = rest.ImpersonationConfig{
		UserName: username,
		Groups:   groups,
	}

	return kubernetes.NewForConfig(cfg)
}

// Check checks access level for verbs on a resource.
func (k *KubeChecker) Check(
	ctx context.Context,
	resource string,
	namespace string, // "" for cluster-scoped
) (map[string]bool, error) {

	verbs := []string{
		"get", "list", "watch",
		"create", "update", "patch", "delete",
	}

	access := make(map[string]bool)

	for _, verb := range verbs {
		sar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      verb,
					Resource:  resource,
					Namespace: namespace,
				},
			},
		}

		resp, err := k.Client.AuthorizationV1().
			SelfSubjectAccessReviews().
			Create(ctx, sar, metav1.CreateOptions{})
		if err != nil {
			return nil, err
		}

		access[verb] = resp.Status.Allowed
	}

	return access, nil
}

