package gate

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// CertReloader serves the server certificate and picks up renewals (for
// example from Let's Encrypt) without a restart.
type CertReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	c := &CertReloader{certFile: certFile, keyFile: keyFile}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CertReloader) load() error {
	st, err := os.Stat(c.certFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	c.cert, c.modTime = &cert, st.ModTime()
	return nil
}

func (c *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checked) > 30*time.Second {
		c.checked = time.Now()
		if st, err := os.Stat(c.certFile); err == nil && !st.ModTime().Equal(c.modTime) {
			// Keep serving the old certificate if the new pair is half-written.
			old, oldMod := c.cert, c.modTime
			if err := c.load(); err != nil {
				c.cert, c.modTime = old, oldMod
				log.Printf("TLS certificate changed but could not be loaded, still serving the old one: %v", err)
			} else if c.cert.Leaf != nil {
				log.Printf("TLS certificate reloaded: %s, issued by %s, expires %s", c.cert.Leaf.Subject.CommonName,
					c.cert.Leaf.Issuer.CommonName, c.cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
			}
		}
	}
	return c.cert, nil
}
