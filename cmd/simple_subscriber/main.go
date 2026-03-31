package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	core "github.com/yanmarques/jails-controller/pkg/core"
)

func main() {
	pubKey, err := os.ReadFile(core.PUBKEY_PATH_IN_JAIL)
	if err != nil {
		log.Fatal(err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		log.Fatal(fmt.Errorf("invalid ed25519 public key %s", core.PUBKEY_PATH_IN_JAIL))
	}

	jailsCtlPubkey := ed25519.PublicKey(pubKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/notify", func(w http.ResponseWriter, r *http.Request) {
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

		log.Printf("got new state: %v", event)
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
	if err := server.ListenAndServeTLS("/cert.pem", "/key.pem"); err != nil {
		log.Fatal(err)
	}
}
