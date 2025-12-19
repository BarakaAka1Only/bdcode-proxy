package filesystem

import (
"context"
"crypto/tls"
"fmt"
)

type FileTLSProvider struct {
	CertFile string
	KeyFile  string
}

func NewFileTLSProvider(certFile, keyFile string) *FileTLSProvider {
	return &FileTLSProvider{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
}

func (p *FileTLSProvider) GetCertificate(ctx context.Context) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair from %s, %s: %w", p.CertFile, p.KeyFile, err)
	}
	return &cert, nil
}
