package kube

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientset returns a Kubernetes clientset using in-cluster config or the
// local kubeconfig file (KUBECONFIG env or ~/.kube/config).
func NewClientset() (*kubernetes.Clientset, error) {
	cfg, err := restConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

// NewDynamicClient returns a dynamic Kubernetes client for CRD access.
func NewDynamicClient() (dynamic.Interface, error) {
	cfg, err := restConfig()
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(cfg)
}

func restConfig() (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = home + "/.kube/config"
	}
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// EnsureNamespace creates a namespace if it does not already exist.
func EnsureNamespace(ctx context.Context, cs *kubernetes.Clientset, name string) error {
	_, err := cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("get namespace %s: %w", name, err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	_, err = cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	return err
}

// GetSecretValue returns the decoded value of a single key from a secret.
func GetSecretValue(ctx context.Context, cs *kubernetes.Clientset, namespace, name, key string) (string, error) {
	secret, err := cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
	}
	v, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", key, namespace, name)
	}
	return string(v), nil
}

// CreateOrUpdateSecret creates a secret or overwrites it if it already exists.
func CreateOrUpdateSecret(ctx context.Context, cs *kubernetes.Clientset, namespace, name string, data map[string][]byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       data,
	}
	_, err := cs.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if k8serrors.IsAlreadyExists(err) {
		_, err = cs.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	}
	return err
}

// GetIngressHosts returns all host names defined across ingress rules in a namespace.
func GetIngressHosts(ctx context.Context, cs *kubernetes.Clientset, namespace string) ([]string, error) {
	ingresses, err := cs.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ingresses in %s: %w", namespace, err)
	}
	var hosts []string
	for _, ing := range ingresses.Items {
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
		}
	}
	return hosts, nil
}

// ApplyFile runs `kubectl apply -f <file>` streaming output to stdout/stderr.
func ApplyFile(file string, extraArgs ...string) error {
	args := append([]string{"apply", "-f", file}, extraArgs...)
	return RunKubectl(args...)
}

// ApplyStdin pipes content into `kubectl apply -f -` with optional extra args.
func ApplyStdin(content []byte, extraArgs ...string) error {
	args := append([]string{"apply", "-f", "-"}, extraArgs...)
	cmd := exec.Command("kubectl", args...)
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunKubectl runs kubectl with the given arguments, streaming stdout/stderr.
func RunKubectl(args ...string) error {
	cmd := exec.Command("kubectl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunKubectlOutput runs kubectl and returns stdout as a trimmed string.
func RunKubectlOutput(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// RunHelm runs helm with the given arguments, streaming stdout/stderr.
func RunHelm(args ...string) error {
	cmd := exec.Command("helm", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
