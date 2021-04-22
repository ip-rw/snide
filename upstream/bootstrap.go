package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/joomcode/errorx"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// NextProtoDQ - During connection establishment, DNS/QUIC support is indicated
// by selecting the ALPN token "dq" in the crypto handshake.
const NextProtoDQ = "doq-i00"

// RootCAs is the CertPool that must be used by all upstreams
// Redefining RootCAs makes sense on iOS to overcome the 15MB memory limit of the NEPacketTunnelProvider
// nolint
var RootCAs *x509.CertPool

// CipherSuites - custom list of TLSv1.2 ciphers
// nolint
var CipherSuites []uint16

type bootstrapper struct {
	address        string      // in form of "tls://one.one.one.one:853"
	resolvers      []*Resolver // list of Resolvers to use to resolve hostname, if necessary
	dialContext    dialHandler // specifies the dial function for creating unencrypted TCP connections.
	resolvedConfig *tls.Config

	current uint64
	sync.RWMutex

	// stores options for AddressToUpstream func:
	// callbacks for checking certificates, timeout,
	// the need to verify the server certificate,
	// the addresses of upstream servers, etc
	options Options
}

func (s *bootstrapper) NextIndex() int {
	return int(atomic.AddUint64(&s.current, uint64(1)) % uint64(len(s.options.ServerIPAddrs)))
}

// newBootstrapperResolved creates a new bootstrapper that already contains resolved config.
// This can be done only in the case when we already know the resolver IP address.
// options -- Upstream customization options
func newBootstrapperResolved(address string, options Options) (*bootstrapper, error) {
	// get a host without port
	host, port, err := getAddressHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("bootstrapper requires port in address %s", address)
	}

	var resolverAddresses []string
	for _, ip := range options.ServerIPAddrs {
		addr := net.JoinHostPort(ip.String(), port)
		resolverAddresses = append(resolverAddresses, addr)
	}
	//rand.Shuffle(len(resolverAddresses), func(i, j int) {
	//	resolverAddresses[i], resolverAddresses[j] = resolverAddresses[j], resolverAddresses[i]
	//})
	b := &bootstrapper{
		address: address,
		options: options,
	}
	b.dialContext = b.createDialContext(resolverAddresses)
	b.resolvedConfig = b.createTLSConfig(host)

	return b, nil
}

// newBootstrapper initializes a new bootstrapper instance
// address -- original resolver address string (i.e. tls://one.one.one.one:853)
// options -- Upstream customization options
func newBootstrapper(address string, options Options) (*bootstrapper, error) {
	resolvers := []*Resolver{}
	if len(options.Bootstrap) != 0 {
		// Create a list of resolvers for parallel lookup
		for _, boot := range options.Bootstrap {
			r, err := NewResolver(boot, options)
			if err != nil {
				return nil, err
			}
			resolvers = append(resolvers, r)
		}
	} else {
		r, _ := NewResolver("", options) // NewResolver("") always succeeds
		// nil resolver if the default one
		resolvers = append(resolvers, r)
	}

	return &bootstrapper{
		address:   address,
		resolvers: resolvers,
		options:   options,
	}, nil
}

// dialHandler specifies the dial function for creating unencrypted TCP connections.
type dialHandler func(ctx context.Context, network, addr string) (net.Conn, error)

// will get usable IP address from Address field, and caches the result
func (s *bootstrapper) get() (*tls.Config, dialHandler, error) {
	s.RLock()
	if s.dialContext != nil && s.resolvedConfig != nil { // fast path
		tlsConfig, dialContext := s.resolvedConfig, s.dialContext
		s.RUnlock()
		return tlsConfig.Clone(), dialContext, nil
	}

	//
	// Slow path: resolve the IP address of the n.address's host
	//

	// get a host without port
	host, port, err := getAddressHostPort(s.address)
	if err != nil {
		addr := s.address
		s.RUnlock()
		return nil, nil, fmt.Errorf("bootstrapper requires port in address %s", addr)
	}

	// if n.address's host is an IP, just use it right away
	ip := net.ParseIP(host)
	if ip != nil {
		s.RUnlock()

		// Upgrade lock to protect n.resolved
		resolverAddress := net.JoinHostPort(host, port)
		s.Lock()
		defer s.Unlock()

		s.dialContext = s.createDialContext([]string{resolverAddress})
		s.resolvedConfig = s.createTLSConfig(host)
		return s.resolvedConfig, s.dialContext, nil
	}

	// Don't lock anymore (we can launch multiple lookup requests at a time)
	// Otherwise, it might mess with the timeout specified for the Upstream
	// See here: https://github.com/AdguardTeam/dnsproxy/issues/15
	s.RUnlock()

	//
	// if it's a hostname
	//

	var ctx context.Context
	if s.options.Timeout > 0 {
		ctxWithTimeout, cancel := context.WithTimeout(context.TODO(), s.options.Timeout)
		defer cancel() // important to avoid a resource leak
		ctx = ctxWithTimeout
	} else {
		ctx = context.Background()
	}

	addrs, err := LookupParallel(ctx, s.resolvers, host)
	if err != nil {
		return nil, nil, errorx.Decorate(err, "failed to lookup %s", host)
	}

	resolved := []string{}
	for _, addr := range addrs {
		if addr.IP.To4() == nil && addr.IP.To16() == nil {
			continue
		}

		resolved = append(resolved, net.JoinHostPort(addr.String(), port))
	}

	if len(resolved) == 0 {
		// couldn't find any suitable IP address
		return nil, nil, fmt.Errorf("couldn't find any suitable IP address for host %s", host)
	}

	s.Lock()
	defer s.Unlock()

	s.dialContext = s.createDialContext(resolved)
	s.resolvedConfig = s.createTLSConfig(host)
	return s.resolvedConfig, s.dialContext, nil
}

var cache = tls.NewLRUClientSessionCache(10000)

// createTLSConfig creates a client TLS config
func (s *bootstrapper) createTLSConfig(host string) *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:            host,
		RootCAs:               &x509.CertPool{},
		CipherSuites:          CipherSuites,
		InsecureSkipVerify:    s.options.InsecureSkipVerify,
		VerifyPeerCertificate: s.options.VerifyServerCertificate,
		ClientSessionCache:    cache,
		Renegotiation:         tls.RenegotiateFreelyAsClient,
	}

	tlsConfig.NextProtos = []string{
		"http/1.1", http2.NextProtoTLS, NextProtoDQ,
	}

	return tlsConfig
}

// createDialContext returns dialContext function that tries to establish connection with all given addresses one by one
func (s *bootstrapper) createDialContext(addresses []string) (dialContext dialHandler) {
	dialer := &net.Dialer{
		Timeout: s.options.Timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{1, 0})
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
			})
		},
	}

	dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var errs []error

		// Return first connection without error
		// Note that we're using bootstrapped resolverAddress instead of what's passed to the function
		//var index int

		for i := 0; i < len(addresses); i++ {
			//index = s.NextIndex()
			resolverAddress := addresses[rand.Intn(len(addresses))]
			log.Debugf("Dialing to %s", resolverAddress)
			start := time.Now()
			con, err := dialer.DialContext(ctx, network, resolverAddress)
			elapsed := time.Since(start) / time.Millisecond

			if err == nil {
				log.Tracef("dialer has successfully initialized connection to %s in %d milliseconds", resolverAddress, elapsed)
				return con, err
			}
			errs = append(errs, err)
			log.Tracef("dialer failed to initialize connection to %s, in %d milliseconds, cause: %s", resolverAddress, elapsed, err)
		}

		if len(errs) == 0 {
			return nil, fmt.Errorf("all dialers failed to initialize connection")
		}
		return nil, errorx.DecorateMany("all dialers failed to initialize connection: ", errs...)
	}
	return
}

// getAddressHostPort splits resolver address into host and port
// returns host, port
func getAddressHostPort(address string) (string, string, error) {
	justHostPort := address
	if strings.Contains(address, "://") {
		parsedURL, err := url.Parse(address)
		if err != nil {
			return "", "", errorx.Decorate(err, "failed to parse %s", address)
		}

		justHostPort = parsedURL.Host
	}

	// convert host to IP if necessary, we know that it's scheme://hostname:port/

	// get a host without port
	return net.SplitHostPort(justHostPort)
}
