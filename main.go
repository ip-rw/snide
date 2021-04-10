package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/paulbellamy/ratecounter"
	"io/ioutil"
	"log"
	"lukechampine.com/frand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var (
	dohUrl      = flag.String("url", "https://cloudflare-dns.com/dns-query", "doh provider url")
	addressFile = flag.String("addr", "cloudflare.txt", "file containing cdn ips to query")
	verbose     = flag.Bool("v", false, "verbose")
	port        = flag.Int("port", 53, "port to run on")

	ips []string
)

func loadIPS(filename string) ([]string, error) {
	if *verbose {
		log.Printf("loading %s...", filename)
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	var ips []string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		ips = append(ips, scan.Text())
	}
	return ips, nil
}

var dialer = net.Dialer{
	Timeout: 5 * time.Second,
}
var (
	cache = tls.NewLRUClientSessionCache(5000)
	tr    = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			ip := ips[frand.Intn(len(ips))]
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		TLSClientConfig: &tls.Config{
			ClientSessionCache: cache,
			Renegotiation:      tls.RenegotiateFreelyAsClient,
		},
		TLSHandshakeTimeout:   5 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		//WriteBufferSize:       9000,
		//ReadBufferSize:        9000,
		//DisableKeepAlives:     true,
		ForceAttemptHTTP2: true,
	}
)

func makeHttpsRequestClient(wire []byte) (respWire []byte, err error) {
	// disable security check for client
	t := tr.Clone()

	//client := &http.Client{Transport: t}
	buff := bytes.NewBuffer(wire)
	req, err := http.NewRequest("POST", *dohUrl, buff)
	req.Header.Add("Content-Type", "application/dns-udpwireformat")
	resp, err := t.RoundTrip(req)
	defer t.CloseIdleConnections()
	//
	//resp, err := client.Post(*dohUrl, "application/dns-udpwireformat", buff)

	if err == nil {
		defer resp.Body.Close()
		if *verbose {
			log.Printf("response status: %s\n", resp.Status)
		}
		if resp.StatusCode != 200 {
			return nil, errors.New(resp.Status)
		}

		respBody, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			return respBody, nil
		} else {
			// io: read error
			return nil, err
		}
	} else {
		// http error
		return nil, err
	}
}

type DNSHandler struct {
	Net string
}

func (s DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	wire, err := r.Pack()
	if err == nil {
		resp, err := makeHttpsRequestClient(wire)
		if err == nil {
			m := new(dns.Msg)
			err := m.Unpack(resp)
			if err == nil {
				m.SetReply(r)
				w.WriteMsg(m)
				qps.Incr(1)
				if *verbose {
					log.Print(m.String())
				}
			} else {
				fps.Incr(1)
				dns.HandleFailed(w, r)
			}
		} else {
			fps.Incr(1)
			if *verbose {
				log.Printf("%s\n", err.Error())
			}
			dns.HandleFailed(w, r)
		}
	} else {
		fps.Incr(1)
		if *verbose {
			log.Printf("error packing message: %s\n", err.Error())
		}
		dns.HandleFailed(w, r)
	}
}

var qps = ratecounter.NewRateCounter(time.Second * 5)
var fps = ratecounter.NewRateCounter(time.Second * 5)

func main() {
	flag.Parse()
	var err error
	ips, err = loadIPS(*addressFile)
	if err != nil {
		flag.PrintDefaults()
		return
	}

	go func() {
		for {
			fmt.Fprintf(os.Stderr, "%d qps, %d fps\n", qps.Rate()/5, fps.Rate()/5)
			time.Sleep(3 * time.Second)
		}
	}()

	go func() {
		handler := DNSHandler{"udp"}
		srv := &dns.Server{Addr: "0.0.0.0:" + strconv.Itoa(*port), Net: "udp"}
		srv.ReusePort = true
		srv.Handler = handler
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s\n", err.Error())
		}
	}()

	go func() {
		handler := DNSHandler{"tcp"}
		srv := &dns.Server{Addr: "0.0.0.0:" + strconv.Itoa(*port), Net: "tcp"}
		srv.ReusePort = true
		srv.Handler = handler
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set tcp listener %s\n", err.Error())
		}
	}()

	log.Printf("running dns server on port %v\n", *port)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Signal (%v) received, stopping\n", s)
}
