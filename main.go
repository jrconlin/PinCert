package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime/pprof"
	"strings"

	flags "github.com/jessevdk/go-flags"
)

var opts struct {
	Profile    string `long:"profile"`
	MemProfile string `long:"memprofile"`
	Host       string `short:"h" long:"host" description:"TLS Host URL"`
	File       string `short:"f" long:"file" description:"TLS Certificate File"`
}

var (
	ErrNotHTTPS    = errors.New("Site not HTTPS")
	ErrInvalidCert = errors.New("Certificate File is invalid")
)

func genHash(cert *x509.Certificate) (hash string, err error) {
	pk := cert.PublicKey.(*rsa.PublicKey)
	// since python doesn't make it easy to get the raw Subject Public Key Info
	// or really do anything with it, going for a more esoteric fix of building
	// a byte array from the key elements.
	log.Printf("%v\n", pk.N)
	b := pk.N.Bytes()
	b = append(b, byte(pk.E))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func getSigFromFile(file string) (source, hash string, err error) {
	log.Printf("Reading from %s\n", file)
	var cert tls.Certificate
	var certDERBlock *pem.Block

	certPEMBlock, err := ioutil.ReadFile(file)
	if err != nil {
		return "", "", nil
	}

	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return "", "", ErrInvalidCert
	}
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", "", err
	}
	hash, err = genHash(x509cert)
	return x509cert.Subject.Organization[0], hash, err
}

func getSigFromHost(url *url.URL) (source, hash string, err error) {
	url.Scheme = "https"
	log.Printf("Reading from URL %s\n", url.String())
	resp, err := http.Get(url.String())
	if err != nil {
		return "", "", err
	}
	switch resp.StatusCode {
	case 301, 302:
		url, err = url.Parse(resp.Header.Get("Location"))
		log.Printf("Redirecting to %s\n", url.String())
		return getSigFromHost(url)
	case 200, 201:
		break
	default:
		log.Printf("Host returned invalid response: %s %s\n", url.String(), resp.Status)
		return "", "", ErrNotHTTPS
	}
	//log.Printf("%+v\n", resp.TLS)
	cert := resp.TLS.VerifiedChains[0][0]
	//cert := resp.TLS.PeerCertificates[0]
	hash, err = genHash(cert)
	log.Printf("Subject %+v\n", cert.Subject)
	return cert.Subject.Organization[0], hash, err
}

func main() {
	var (
		url  url.URL
		err  error
		s, h string
	)

	args, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		return
	}

	if opts.Profile != "" {
		log.Printf("Creating profile %s...\n", opts.Profile)
		f, err := os.Create(opts.Profile)
		if err != nil {
			log.Fatalf("Profile creation failed: %s\n", err.Error())
			return
		}
		pprof.StartCPUProfile(f)
		defer func() {
			log.Printf("Writing app profile...\n")
			pprof.StopCPUProfile()
		}()
	}
	if opts.MemProfile != "" {
		defer func() {
			f, err := os.Create(opts.MemProfile)
			if err != nil {
				log.Fatalf("Memory Profile creation failed: %s\n", err.Error())
				return
			}
			log.Printf("Writing Memory profile...\n")
			pprof.WriteHeapProfile(f)
			f.Close()
		}()
	}

	switch {
	case opts.File != "":
		s, h, err = getSigFromFile(opts.File)
	case opts.Host != "":
		url, err := url.Parse(opts.Host)
		if err != nil {
			log.Fatalf("Could not parse Host: %s", err.Error())
			return
		}
		s, h, err = getSigFromHost(url)
		if err != nil {
			log.Fatalf("Could not get data from host:%s %s", opts.Host, err.Error())
		}
	default:
		for _, arg := range args[1:] {
			if strings.Contains(arg, "http") {
				if url, err := url.Parse(arg); err == nil {
					s, h, err = getSigFromHost(url)
				}
			} else {
				s, h, err = getSigFromFile(arg)
			}
			if err != nil {
				log.Printf("## Could not process %s: %s\n", arg, err.Error())
				continue
			}
		}
	}
	fmt.Printf("Source: %s\nHash: %s\n", s, h)
}
