package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadServiceConfiguration(t *testing.T) {
	t.Setenv("LANTERNFISH_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("LANTERNFISH_MASTER_KEY_FILE", "")
	t.Setenv("LANTERNFISH_MASTER_KEY_DPAPI_FILE", "")
	t.Setenv("LANTERNFISH_SERVICE_NETWORK", "10.20.0.0/24")
	t.Setenv("LANTERNFISH_SERVICE_LISTEN", "10.20.0.2:8096")
	t.Setenv("LANTERNFISH_SERVICE_CLIENTS", "seerr=10.20.0.4")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServiceListen != "10.20.0.2:8096" || len(cfg.ServiceClients) != 1 || cfg.ServiceClients[0].Name != "seerr" || cfg.ServiceClients[0].IP != "10.20.0.4" {
		t.Fatalf("service configuration lost: %+v", cfg.ServiceClients)
	}
	t.Setenv("LANTERNFISH_SERVICE_CLIENTS", "10.20.0.4")
	if _, err := loadConfig(); err == nil {
		t.Fatal("accepted malformed service clients")
	}
}

func TestLoadOptionalServiceParameters(t *testing.T) {
	t.Setenv("LANTERNFISH_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("LANTERNFISH_MASTER_KEY_FILE", "")
	t.Setenv("LANTERNFISH_MASTER_KEY_DPAPI_FILE", "")
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(file, []byte(`[{"name":"seerr","ip":"10.20.0.4","permissions":[],"max_concurrent":2}]`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LANTERNFISH_SERVICE_CLIENTS", "")
	t.Setenv("LANTERNFISH_SERVICE_CLIENTS_FILE", file)
	t.Setenv("LANTERNFISH_SERVICE_AUTH", "mtls")
	t.Setenv("LANTERNFISH_SERVICE_TIMEOUT", "90s")
	t.Setenv("LANTERNFISH_SERVICE_MAX_CONCURRENT", "4")
	t.Setenv("LANTERNFISH_SERVICE_REQUESTS_PER_MINUTE", "60")
	t.Setenv("LANTERNFISH_SERVICE_MAX_BODY_BYTES", "1048576")
	t.Setenv("LANTERNFISH_SERVICE_ALERT_FAILURES", "5")
	t.Setenv("LANTERNFISH_SERVICE_ALERT_WINDOW", "10m")
	t.Setenv("LANTERNFISH_SERVICE_CERT_WARN_BEFORE", "168h")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServiceAuth != "mtls" || cfg.ServiceTimeout != 90*time.Second || cfg.ServiceMaxConcurrent != 4 || cfg.ServiceRequestsPerMinute != 60 || cfg.ServiceMaxBodyBytes != 1048576 || cfg.ServiceAlertFailures != 5 || cfg.ServiceAlertWindow != 10*time.Minute || cfg.ServiceCertWarnBefore != 168*time.Hour || cfg.ServiceClients[0].Permissions == nil {
		t.Fatal("optional service parameters lost")
	}
	t.Setenv("LANTERNFISH_SERVICE_CLIENTS", "seerr=10.20.0.4")
	if _, err := loadConfig(); err == nil {
		t.Fatal("ambiguous client sources accepted")
	}
	t.Setenv("LANTERNFISH_SERVICE_CLIENTS", "")
	t.Setenv("LANTERNFISH_SERVICE_TIMEOUT", "bad")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid timeout accepted")
	}
}
