package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	core "github.com/yanmarques/jails-controller/pkg/core"
)

type Target struct {
	Labels  map[string]string `json:"labels"`
	Targets []string          `json:"targets"`
}

const HINT_KEY = "metricsPort"
const DEFAULT_TARGETSFILE_MODE = 0644

func main() {
	core.InitLogging()

	tlsPubPath := flag.String("certPath", "cert.pem", "TLS public certificate path")
	tlsPrivPath := flag.String("keyPath", "key.pem", "TLS private key path")
	targetsFile := flag.String("targetsFile", "/usr/local/etc/prometheus/targets.json", "Path to Prometheus dynamic targets")

	flag.Parse()

	pubKey, err := os.ReadFile(core.PUBKEY_PATH_IN_JAIL)
	if err != nil {
		log.Fatal(err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		log.Fatal(fmt.Errorf("invalid ed25519 public key %s", core.PUBKEY_PATH_IN_JAIL))
	}

	jailsCtlPubkey := ed25519.PublicKey(pubKey)

	var targetsFileMode os.FileMode

	targetsFileStat, err := os.Stat(*targetsFile)
	if err != nil {
		if os.IsNotExist(err) {
			targetsFileMode = os.FileMode(DEFAULT_TARGETSFILE_MODE)
		} else {
			log.Fatal(err)
		}
	} else {
		if targetsFileMode.IsDir() {
			log.Fatalf("targets file can not be a directory: %s", *targetsFile)
		}

		targetsFileMode = targetsFileStat.Mode()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/notify", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request: url=%s remote=%s", r.URL, r.RemoteAddr)

		if r.Header.Get("content-type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*4))

		if err != nil {
			log.Printf("reading request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		event, err := core.ParseEventSync(body, jailsCtlPubkey)
		if err != nil {
			log.Printf("parsing event: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		targets := []*Target{}
		for _, jail := range event.Jails {
			ip, err := netip.ParseAddr(jail.IpAddr)
			if err != nil {
				log.Printf("[ERROR] jail ip addr is invalid: %s", jail.IpAddr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			metricsPortStr, ok := jail.Hints[HINT_KEY]
			if !ok {
				continue
			}

			metricsPort, err := strconv.Atoi(metricsPortStr)
			if err != nil {
				log.Printf("failed to parse metrics %s port in jail %s: %v", metricsPortStr, jail.Name, err)
				continue
			}

			if metricsPort <= 0 || metricsPort > 65535 {
				log.Printf("invalid metrics port %d for jail %s", metricsPort, jail.Name)
				continue
			}

			targets = append(targets, &Target{
				Labels: map[string]string{
					"name":     jail.Name,
					"hostname": jail.Hostname,
				},
				Targets: []string{
					ip.String() + ":" + strconv.Itoa(metricsPort),
				},
			})
		}

		data, err := json.Marshal(&targets)
		if err != nil {
			log.Printf("%v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = os.WriteFile(*targetsFile, data, targetsFileMode)
		if err != nil {
			log.Printf("failed to write to targets file: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Printf("new prometheus targets applied: %d", len(targets))
		w.WriteHeader(http.StatusNoContent)
	})

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	server := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Println("Starting HTTPS server on :8443")
	if err := server.ListenAndServeTLS(*tlsPubPath, *tlsPrivPath); err != nil {
		log.Fatal(err)
	}
}
