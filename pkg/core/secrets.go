package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	SECRET_TYPE_PASSWORD = "password"
	SECRET_TYPE_TOKEN    = "token"
	SECRET_TYPE_TLS_CERT = "tls"

	LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
	UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	NUMBERS   = "0123456789"
	SPECIAL   = "!@#$%^&*()-_=+[]{}|;:,.<>?"

	DEFAULT_PASSWORD_LEN = 32
)

type TlsCertSecret struct {
	PrivKey []byte
	Cert    []byte
}

type SecretsInfo struct {
	Passwords map[string]string
	Tokens    map[string]string
	TlsCerts  map[string]*TlsCertSecret
	RootCA    *CertificateAuthority
}

type CertificateAuthority struct {
	PrivKey []byte
	Cert    []byte

	template *x509.Certificate
}

type SecretManager struct {
	Inner    *SecretsInfo
	FilePath string
}

func GeneratePassword(length int64, specialChars string, excludeChars bool) (string, error) {
	allChars := LOWERCASE + UPPERCASE + NUMBERS
	if !excludeChars {
		allChars += specialChars
	}

	var password strings.Builder

	maxInt := big.NewInt(length)

	for range length {
		randIdx, err := rand.Int(rand.Reader, maxInt)
		if err != nil {
			return "", err
		}

		password.WriteByte(allChars[randIdx.Int64()])
	}

	return password.String(), nil
}

func ImportSecretManager(filePath string) (*SecretManager, error) {
	var inner SecretsInfo

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &inner)
	if err != nil {
		return nil, err
	}

	pemDecoded, _ := pem.Decode(inner.RootCA.Cert)

	inner.RootCA.template, err = x509.ParseCertificate(pemDecoded.Bytes)
	if err != nil {
		return nil, err
	}

	return &SecretManager{
		FilePath: filePath,
		Inner:    &inner,
	}, nil
}

func NewSecretManager(filePath string) (*SecretManager, error) {
	caPriv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// TODO: configure CA expiration
	caTemplate := &x509.Certificate{
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		return nil, err
	}

	privDer, err := x509.MarshalPKCS8PrivateKey(caPriv)
	if err != nil {
		return nil, err
	}

	return &SecretManager{
		FilePath: filePath,
		Inner: &SecretsInfo{
			Passwords: map[string]string{},
			Tokens:    map[string]string{},
			TlsCerts:  map[string]*TlsCertSecret{},
			RootCA: &CertificateAuthority{
				template: caTemplate,
				PrivKey:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDer}),
				Cert:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert}),
			},
		},
	}, nil
}

func (s *SecretManager) Create(manifest *SecretManifest) error {
	if manifest.SecretType == SECRET_TYPE_PASSWORD {
		specialChars := manifest.SpecialChars
		if specialChars == "" {
			specialChars = SPECIAL
		}

		length := manifest.Length
		if length <= 0 {
			length = DEFAULT_PASSWORD_LEN
		}

		password, err := GeneratePassword(length, specialChars, manifest.ExcludeChars)
		if err != nil {
			return err
		}

		s.Inner.Passwords[manifest.Name] = password

		return nil
	}

	if manifest.SecretType == SECRET_TYPE_TOKEN {
		box := make([]byte, manifest.Length)
		rand.Read(box)

		s.Inner.Tokens[manifest.Name] = base64.StdEncoding.EncodeToString(box)

		return nil
	}

	if manifest.SecretType == SECRET_TYPE_TLS_CERT {
		bits := manifest.Bits
		if bits == 0 {
			bits = 2048
		}
		tlsPrivKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return err
		}

		pemDecoded, _ := pem.Decode(s.Inner.RootCA.PrivKey)

		caPriv, err := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)
		if err != nil {
			return err
		}

		// FIXME: configure expiration
		tlsCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(3, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			KeyUsage: x509.KeyUsageDigitalSignature,
			DNSNames: manifest.DNSNames,
		}, s.Inner.RootCA.template, tlsPrivKey.Public(), caPriv)

		if err != nil {
			return err
		}

		tlsPrivDer, err := x509.MarshalPKCS8PrivateKey(tlsPrivKey)
		if err != nil {
			return err
		}

		s.Inner.TlsCerts[manifest.Name] = &TlsCertSecret{
			PrivKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: tlsPrivDer}),
			Cert:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert}),
		}

		return nil
	}

	return fmt.Errorf("unknown secret type %s", manifest.SecretType)
}

func (s *SecretManager) Save() error {
	content, err := json.Marshal(s.Inner)
	if err != nil {
		return err
	}

	return os.WriteFile(s.FilePath, content, os.FileMode(0700))
}

func (s *SecretManager) Content(secretType string, name string) ([]byte, bool) {
	switch secretType {
	case SECRET_TYPE_PASSWORD:
		passwd, ok := s.Inner.Passwords[name]
		if !ok {
			return nil, false
		}

		return []byte(passwd), true
	case SECRET_TYPE_TOKEN:
		token, ok := s.Inner.Tokens[name]
		if !ok {
			return nil, false
		}

		return []byte(token), true
	case SECRET_TYPE_TLS_CERT:
		certType := ""
		elements := strings.Split(name, "/")
		if len(elements) == 2 {
			certType = elements[1]
		}

		tlsCert, ok := s.Inner.TlsCerts[elements[0]]
		if !ok {
			return nil, false
		}

		switch certType {
		case "privKey":
			return tlsCert.PrivKey, true
		default:
			return tlsCert.Cert, true
		}
	}

	return nil, false
}

func (s *SecretManager) Destroy(manifest *SecretManifest) error {
	switch manifest.SecretType {
	case SECRET_TYPE_PASSWORD:
		delete(s.Inner.Passwords, manifest.Name)
	case SECRET_TYPE_TOKEN:
		delete(s.Inner.Tokens, manifest.Name)
	case SECRET_TYPE_TLS_CERT:
		delete(s.Inner.TlsCerts, manifest.Name)
	default:
		return fmt.Errorf("unknown secret type %s", manifest.SecretType)
	}

	return nil
}
