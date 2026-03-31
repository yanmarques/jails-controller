package controller

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

type LazyPackage struct {
	Event            *LazyEvent
	DeliveryAttempts int
	HttpClient       *http.Client
}

type LazyEvent struct {
	Server            string
	ServerFingerprint []byte
	Address           ServerAddr
	Payload           any
}

type ServerAddr struct {
	IpAddr netip.Addr
	Port   int
}

func (r *ServerAddr) String() string {
	return r.IpAddr.String() + ":" + strconv.Itoa(r.Port)
}

func (e *LazyEvent) Url() string {
	return "https://" + e.Address.String() + "/notify"
}

type LazyEventNotifier struct {
	Queue      map[string]LazyPackage
	Timeout    time.Duration
	MaxRetries int
}

func NewEventNotifier(maxRetries int, timeout time.Duration) *LazyEventNotifier {
	return &LazyEventNotifier{
		Queue:      map[string]LazyPackage{},
		Timeout:    timeout,
		MaxRetries: maxRetries,
	}
}

func sumFingerprint(cert []byte) ([]byte, error) {
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.MarshalPKIXPublicKey(parsed.PublicKey)
	if err != nil {
		return nil, err
	}

	fingerprint := sha256.Sum256(pubKey)

	return fingerprint[:], nil
}

func (n *LazyEventNotifier) NewHttpClientForServer(server string, serverFingerprint []byte) (*http.Client, error) {
	transport := http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,

			// perform certificate fingprint checking, ignore subjectName
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("server missing certificate: %s", server)
				}

				fingerprint, err := sumFingerprint(rawCerts[0])
				if err != nil {
					return err
				}

				if !slices.Equal(fingerprint, serverFingerprint) {
					return fmt.Errorf("certificate mismatch: %s", server)
				}

				return nil
			},
		},
	}

	return &http.Client{
		Timeout:   n.Timeout,
		Transport: &transport,
	}, nil
}

func (n *LazyEventNotifier) RetryFailures(confirmedServers map[string]ServerAddr) {
	for server := range n.Queue {
		addr, confirmed := confirmedServers[server]
		if !confirmed {
			delete(n.Queue, server)
			continue
		}

		if addr.String() != n.Queue[server].Event.Address.String() {
			log.Printf("notifier: server changed address %s", server)
		}

		n.Queue[server].Event.Address = addr
	}

	for server, pkg := range n.Queue {
		attempts := pkg.DeliveryAttempts + 1
		err := oops.Err(n.sendNotification(pkg.Event, attempts))
		if err != nil {
			if attempts >= n.MaxRetries {
				log.Printf("notifier: tried notifying server %s %d times, none succeeded. giving up",
					server, attempts)
				delete(n.Queue, server)
			}
		}
	}
}

func (n *LazyEventNotifier) Notify(event *LazyEvent) error {
	return n.sendNotification(event, 1)
}

func (n *LazyEventNotifier) sendNotification(event *LazyEvent, attempts int) error {
	body, err := json.Marshal(event.Payload)
	if err != nil {
		return err
	}

	var httpClient *http.Client

	_, ok := n.Queue[event.Server]
	if ok {
		httpClient = n.Queue[event.Server].HttpClient
	} else {
		httpClient, err = n.NewHttpClientForServer(event.Server, event.ServerFingerprint)
		if err != nil {
			return err
		}
	}

	resp, err := httpClient.Post(event.Url(), "application/json", bytes.NewReader(body))
	if err != nil {
		n.Queue[event.Server] = LazyPackage{
			Event:            event,
			DeliveryAttempts: attempts,
			HttpClient:       httpClient,
		}

		return err
	}

	defer resp.Body.Close()

	var respBody []byte
	_, err = resp.Body.Read(respBody)

	if err != nil || resp.StatusCode != http.StatusNoContent {
		n.Queue[event.Server] = LazyPackage{
			Event:            event,
			DeliveryAttempts: attempts,
			HttpClient:       httpClient,
		}
	}

	return err
}
