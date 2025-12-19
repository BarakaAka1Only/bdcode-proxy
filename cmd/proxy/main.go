package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/api"
	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/core"
	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/discovery/kubernetes"
	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/discovery/memory"
	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/protocol/postgresql"
	"github.com/hasirciogluhq/xdatabase-proxy/cmd/proxy/internal/storage/filesystem"

	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	log.Println("Starting xdatabase-proxy...")

	// Check if proxy is enabled
	if os.Getenv("POSTGRESQL_PROXY_ENABLED") != "true" {
		log.Println("PostgreSQL proxy is not enabled (POSTGRESQL_PROXY_ENABLED != true)")
		// We might still want to run health checks or just exit?
		// For now, let's assume we just block or exit.
		// But usually a pod runs the proxy if it's deployed.
		// Let's just log and continue, or maybe return.
		// The original code returned.
		return
	}

	// 1. Health Server
	healthServer := api.NewHealthServer(":8080")
	healthServer.Start()

	// 2. Infrastructure Layer (Resolver)
	var resolver core.BackendResolver
	var clientset *k8s.Clientset

	if staticBackends := os.Getenv("STATIC_BACKENDS"); staticBackends != "" {
		log.Println("Using Memory Resolver (STATIC_BACKENDS set)")
		memResolver, err := memory.NewResolver(staticBackends)
		if err != nil {
			log.Fatalf("Failed to create memory resolver: %v", err)
		}
		resolver = memResolver
	} else {
		// Kubernetes Resolver
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}

		// Use KUBE_CONTEXT if provided (dev mode)
		contextName := os.Getenv("KUBE_CONTEXT")

		configOverrides := &clientcmd.ConfigOverrides{}
		if contextName != "" {
			configOverrides.CurrentContext = contextName
		}

		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			configOverrides,
		).ClientConfig()

		if err != nil {
			// Fallback to in-cluster config
			config, err = clientcmd.BuildConfigFromFlags("", "")
			if err != nil {
				log.Fatalf("Failed to build kubeconfig: %v", err)
			}
		}

		clientset, err = k8s.NewForConfig(config)
		if err != nil {
			log.Fatalf("Failed to create k8s client: %v", err)
		}
		resolver = kubernetes.NewK8sResolver(clientset)
	}

	// 3. TLS Provider
	var tlsProvider core.TLSProvider

	// Priority 1: File-based TLS (Explicit configuration)
	if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" {
		keyFile := os.Getenv("TLS_KEY_FILE")
		if keyFile == "" {
			log.Fatal("TLS_KEY_FILE must be set when TLS_CERT_FILE is set")
		}
		log.Printf("Using File TLS provider (cert: %s, key: %s)", certFile, keyFile)
		tlsProvider = filesystem.NewFileTLSProvider(certFile, keyFile)
	} else if secretName := os.Getenv("TLS_SECRET_NAME"); secretName != "" {
		// Priority 2: Kubernetes Secret (Explicit configuration)
		if clientset == nil {
			log.Fatal("Cannot use Kubernetes TLS provider without Kubernetes environment (STATIC_BACKENDS is set)")
		}
		namespace := os.Getenv("POD_NAMESPACE")
		if namespace == "" {
			namespace = os.Getenv("NAMESPACE") // Fallback to generic NAMESPACE env
		}
		if namespace == "" {
			namespace = "default"
		}
		log.Printf("Using Kubernetes TLS provider (secret: %s/%s)", namespace, secretName)
		tlsProvider = kubernetes.NewK8sTLSProvider(clientset, namespace, secretName)
	} else {
		// Priority 3: Self-Signed (Development/Default)
		log.Println("Using Self-Signed Memory TLS provider (Development Mode)")
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("Failed to generate self-signed cert: %v", err)
		}
		tlsProvider = &memoryTLSProvider{cert: &cert}
	}

	// Load initial certificate
	cert, err := tlsProvider.GetCertificate(context.Background())
	if err != nil {
		log.Fatalf("Failed to load initial certificate: %v", err)
	}

	// 4. Protocol Layer (PostgreSQL)
	protocolHandler := &postgresql.PostgresHandler{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
		},
	}

	// 5. Core Layer (Proxy)
	startPort := os.Getenv("POSTGRESQL_PROXY_START_PORT")
	if startPort == "" {
		startPort = "5432"
	}

	listener, err := net.Listen("tcp", ":"+startPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Printf("Listening on :%s", startPort)

	server := &core.Server{
		Listener:        listener,
		Resolver:        resolver,
		ProtocolHandler: protocolHandler,
	}

	// Mark as ready
	healthServer.SetReady(true)

	if err := server.Serve(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// memoryTLSProvider is a simple in-memory implementation for development
type memoryTLSProvider struct {
	cert *tls.Certificate
}

func (p *memoryTLSProvider) GetCertificate(ctx context.Context) (*tls.Certificate, error) {
	return p.cert, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"xdatabase-proxy"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
