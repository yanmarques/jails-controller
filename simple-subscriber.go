package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const PUBKEY_PATH_IN_JAIL = "/var/run/jails-controller.pubkey"

type EventJailSync struct {
	Name   string
	IpAddr string
}

type EventSyncState struct {
	Signature    string
	Verification string
	Jails        []EventJailSync
}

func main() {
	pubKey, err := os.ReadFile(PUBKEY_PATH_IN_JAIL)
	if err != nil {
		log.Fatal(err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		log.Fatal(fmt.Errorf("invalid ed25519 public key %s", PUBKEY_PATH_IN_JAIL))
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

		var event EventSyncState

		err = json.Unmarshal(body, &event)
		if err != nil {
			log.Printf("parsing json body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		msg, err := hex.DecodeString(event.Verification)
		if err != nil {
			log.Printf("parsing verification message: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sig, err := hex.DecodeString(event.Signature)
		if err != nil {
			log.Printf("parsing signature: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !ed25519.Verify(jailsCtlPubkey, msg, sig) {
			log.Printf("wrong signature, spook detected at address %s", r.RemoteAddr)
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
