package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	core "github.com/yanmarques/jails-controller/pkg/core"
)

const DEFAULT_ZONEFILE_MODE = 0644

// Invalid because dns authority zones already use those,
// and overriding them would be bad
var RESERVED_HOSTNAMES = []string{"ns", "admin"}

func main() {
	core.InitLogging()

	tlsPubPath := flag.String("certPath", "cert.pem", "TLS public certificate path")
	tlsPrivPath := flag.String("keyPath", "key.pem", "TLS private key path")
	zoneFile := flag.String("zoneFile", "/usr/local/etc/coredns/zones/zonefile", "Path to unbound zonefile")
	domain := flag.String("domain", "cluster.local", "Domain to configure the zonefile")
	ttl := flag.Int("ttl", 300, "TTL to configure the zonefile")

	flag.Parse()

	pubKey, err := os.ReadFile(core.PUBKEY_PATH_IN_JAIL)
	if err != nil {
		log.Fatal(err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		log.Fatal(fmt.Errorf("invalid ed25519 public key %s", core.PUBKEY_PATH_IN_JAIL))
	}

	jailsCtlPubkey := ed25519.PublicKey(pubKey)

	var selfIpAddr net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addresses, err := iface.Addrs()
		if err != nil {
			log.Fatal(err)
		}

		for _, addr := range addresses {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.IsLoopback() {
					continue
				}

				selfIpAddr = ipNet.IP
				break
			}
		}
	}

	if selfIpAddr == nil {
		log.Fatalf("unable to determine the ethernet ip address")
	}

	header := "$ORIGIN " + *domain + ".\n"
	header += "$TTL " + strconv.Itoa(*ttl) + "\n"
	header += `@   IN SOA ns.` + *domain + `. admin.` + *domain + `. (
        2026040101 ; serial
        3600       ; refresh
        600        ; retry
        86400      ; expire
        3600       ; minimum
)

@ IN NS ns.` + *domain + `.
ns IN A ` + selfIpAddr.String() + `
`
	var zoneFileMode os.FileMode

	zoneFileStat, err := os.Stat(*zoneFile)
	if err != nil {
		if os.IsNotExist(err) {
			zoneFileMode = os.FileMode(DEFAULT_ZONEFILE_MODE)
		} else {
			log.Fatal(err)
		}
	} else {
		if zoneFileMode.IsDir() {
			log.Fatalf("zoneFile can not be a directory: %s", *zoneFile)
		}

		zoneFileMode = zoneFileStat.Mode()
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

		var records strings.Builder
		records.WriteString(header)

		// TODO: validate against invalid names, like ns or admin
		for _, jail := range event.Jails {
			if !core.ValidHostname(jail.Name) {
				log.Printf("[ERROR] invalid jail name: %s", jail.Name)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if slices.Contains(RESERVED_HOSTNAMES, jail.Name) {
				log.Printf("[ERROR] jail name is reserved: %s", jail.Name)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ip, err := netip.ParseAddr(jail.IpAddr)
			if err != nil {
				log.Printf("[ERROR] jail ip addr is invalid: %s", jail.IpAddr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			_, err = records.WriteString(jail.Name + "\tIN A\t" + ip.String() + "\n")
			if err != nil {
				log.Printf("building new coredns zonefile: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		newConf := []byte(records.String())

		err = os.WriteFile(*zoneFile, newConf, zoneFileMode)
		if err != nil {
			log.Printf("failed to write to zonefile: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		log.Printf("new coredns zonefile applied: %v", event)
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
