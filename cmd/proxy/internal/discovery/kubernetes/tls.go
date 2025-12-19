package kubernetes

import (
"context"
"crypto/tls"
"fmt"

corev1 "k8s.io/api/core/v1"
metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
"k8s.io/client-go/kubernetes"
)

type K8sTLSProvider struct {
	clientset *kubernetes.Clientset
	namespace string
	secretName string
}

func NewK8sTLSProvider(clientset *kubernetes.Clientset, namespace, secretName string) *K8sTLSProvider {
	return &K8sTLSProvider{
		clientset:  clientset,
		namespace:  namespace,
		secretName: secretName,
	}
}

func (p *K8sTLSProvider) GetCertificate(ctx context.Context) (*tls.Certificate, error) {
	secret, err := p.clientset.CoreV1().Secrets(p.namespace).Get(ctx, p.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", p.namespace, p.secretName, err)
	}

	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("secret missing %s", corev1.TLSCertKey)
	}
	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("secret missing %s", corev1.TLSPrivateKeyKey)
	}

	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 key pair: %w", err)
	}

	return &cert, nil
}
