package generator

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// GenerateManifests generates RBAC manifests (Role/Binding or ClusterRole/Binding).
func GenerateManifests(
	name string,
	isServiceAccount bool,
	resource string,
	group string,
	verbs []string,
	namespace string,
	namespaced bool,
) ([]byte, []byte, error) {

	var roleBytes, bindingBytes []byte

	if namespaced {
		// Role + RoleBinding
		roleName := fmt.Sprintf("%s-role", name)
		bindingName := fmt.Sprintf("%s-binding", name)

		role := &rbacv1.Role{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "rbac.authorization.k8s.io/v1",
				Kind:       "Role",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      roleName,
				Namespace: namespace,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{group},
					Resources: []string{resource},
					Verbs:     verbs,
				},
			},
		}
		if group == "" {
			role.Rules[0].APIGroups = []string{""}
		}

		subject := rbacv1.Subject{
			Kind: "User",
			Name: name,
		}
		if isServiceAccount {
			subject.Kind = "ServiceAccount"
			subject.Name = name
			subject.Namespace = namespace
		}

		binding := &rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "rbac.authorization.k8s.io/v1",
				Kind:       "RoleBinding",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: namespace,
			},
			Subjects: []rbacv1.Subject{subject},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     roleName,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}

		roleBytes, _ = yaml.Marshal(role)
		bindingBytes, _ = yaml.Marshal(binding)

	} else {
		// ClusterRole + ClusterRoleBinding
		roleName := fmt.Sprintf("%s-clusterrole", name)
		bindingName := fmt.Sprintf("%s-clusterbinding", name)

		role := &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "rbac.authorization.k8s.io/v1",
				Kind:       "ClusterRole",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: roleName,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{group},
					Resources: []string{resource},
					Verbs:     verbs,
				},
			},
		}
		if group == "" {
			role.Rules[0].APIGroups = []string{""}
		}

		subject := rbacv1.Subject{
			Kind: "User",
			Name: name,
		}
		if isServiceAccount {
			subject.Kind = "ServiceAccount"
			subject.Name = name
			if namespace == "" {
				subject.Namespace = "default"
			} else {
				subject.Namespace = namespace
			}
		}

		binding := &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "rbac.authorization.k8s.io/v1",
				Kind:       "ClusterRoleBinding",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: bindingName,
			},
			Subjects: []rbacv1.Subject{subject},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     roleName,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}

		roleBytes, _ = yaml.Marshal(role)
		bindingBytes, _ = yaml.Marshal(binding)
	}

	return roleBytes, bindingBytes, nil
}
