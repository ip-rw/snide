package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/ip-rw/snide/proxy/internal/specialized"
	"github.com/ip-rw/snide/upstream"
	"github.com/miekg/dns"
	"github.com/paulbellamy/ratecounter"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultCacheSize       = 65536
	connectionTimeout      = 30 * time.Second
	connectionsPerUpstream = 10000
	refreshQueueSize       = 50000
	timerResolution        = 1 * time.Second
)

var qps = ratecounter.NewRateCounter(time.Second * 5)
var fps = ratecounter.NewRateCounter(time.Second * 5)

// Server is a caching DNS proxy that upgrades DNS to DNS over TLS.
type Server struct {
	cache     *cache
	upstreams []*upstream.Upstream
	rq        chan *dns.Msg
	Dial      func(addr string, cfg *tls.Config) (net.Conn, error)

	mu          sync.RWMutex
	currentTime time.Time
	startTime   time.Time
	ips         []string
}

// NewServer constructs a new server but does not start it, use Run to start it afterwards.
// Calling New(0) is valid and comes with working defaults:
// * If cacheSize is 0 a default value will be used. to disable caches use a negative value.
// * If no upstream servers are specified default ones will be used.
func NewServer(cacheSize int, evictMetrics bool, upstreamServers ...string) *Server {
	switch {
	case cacheSize == 0:
		cacheSize = defaultCacheSize
	case cacheSize < 0:
		cacheSize = 0
	}
	cache, err := newCache(cacheSize, evictMetrics)
	if err != nil {
		log.Fatal("Unable to initialize the cache")
	}
	s := &Server{
		cache: cache,
		rq:    make(chan *dns.Msg, refreshQueueSize),
		ips:   []string{},
		Dial: func(addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial("tcp", addr, cfg)
		},
	}
	if len(upstreamServers) == 0 {
		cd, _ := s.NewUpstream("https://cloudflare-dns.com/dns-query@cloudflare.txt")
		s.upstreams = []*upstream.Upstream{
			&cd,
		}
	} else {
		for _, addr := range upstreamServers {
			up, err := s.NewUpstream(addr)
			if err != nil {
				log.WithError(err).Warn("error parsing upstream")
				continue
			}
			s.upstreams = append(s.upstreams, &up)
		}
	}
	return s
}
func (s *Server) NewUpstream(upstreamServer string) (u upstream.Upstream, err error) {
	serverComponents := strings.Split(upstreamServer, "@")
	if len(serverComponents) == 2 {
		upstreamServer = serverComponents[0]
		u, err = upstream.AddressToUpstream(serverComponents[0], upstream.Options{
			Timeout:            10 * time.Second,
			InsecureSkipVerify: true,
			ServerIPAddrs:      loadIPS(serverComponents[1]),
		})
	} else {
		u, err = upstream.AddressToUpstream(upstreamServer, upstream.Options{
			Timeout:            10 * time.Second,
			InsecureSkipVerify: true,
		})
	}
	return u, err
}

func loadIPS(filename string) []net.IP {
	log.Printf("loading %s...", filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	if f == nil {
		return nil
	}
	var ips []net.IP
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		ips = append(ips, net.ParseIP(scan.Text()))
	}
	return ips
}

// Run runs the server. The server will gracefully shutdown when context is canceled.
func (s *Server) Run(ctx context.Context, addr string) error {
	go func() {
		for {
			qr := qps.Rate() / 5
			fr := fps.Rate() / 5
			if qr > 50 || fr > 50 {
				log.Printf("%d qps, %d fps\n", qps.Rate()/5, fps.Rate()/5)
			}
			time.Sleep(3 * time.Second)
		}
	}()

	mux := dns.NewServeMux()
	mux.Handle(".", s)

	servers := []*dns.Server{
		{Addr: addr, Net: "tcp", Handler: mux},
		{Addr: addr, Net: "udp", Handler: mux},
	}

	g, ctx := errgroup.WithContext(ctx)

	go func() {
		<-ctx.Done()
		for _, s := range servers {
			_ = s.Shutdown()
		}
	}()

	go s.timer(ctx)

	for _, s := range servers {
		s := s
		g.Go(func() error { return s.ListenAndServe() })
	}

	s.startTime = time.Now()
	log.Infof("DNS forwarder listening on %v", addr)
	return g.Wait()
}

// ServeDNS implements miekg/dns.Handler for Server.
func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	inboundIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Debugf("Question from %s: %q", inboundIP, q.Question[0])
	m := s.getAnswer(q)
	if m == nil {
		dns.HandleFailed(w, q)
		return
	}
	if err := w.WriteMsg(m); err != nil {
		log.Warnf("Write message failed, message: %v, error: %v", m, err)
	}
}

type debugStats struct {
	CacheMetrics       specialized.CacheMetrics
	CacheLen, CacheCap int
	Uptime             string
}

// DebugHandler returns an http.Handler that serves debug stats.
func (s *Server) DebugHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf, err := json.MarshalIndent(debugStats{
			s.cache.c.Metrics(),
			s.cache.c.Len(),
			s.cache.c.Cap(),
			time.Since(s.startTime).String(),
		}, "", " ")
		if err != nil {
			http.Error(w, "Unable to retrieve debug info", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf)
	})
}

func (s *Server) getAnswer(q *dns.Msg) *dns.Msg {
	m, ok := s.cache.get(q)
	// Cache HIT.
	if ok {
		return m
	}
	// If there is a cache HIT with an expired TTL, speculatively return the cache entry anyway with a short TTL, and refresh it.
	if !ok && m != nil {
		s.refresh(q)
		return m
	}
	// If there is a cache MISS, forward the message upstream and return the answer.
	// miek/dns does not pass a context so we fallback to Background.
	return s.forwardMessageAndCacheResponse(q)
}

func (s *Server) refresh(q *dns.Msg) {
	select {
	case s.rq <- q:
	default:
	}
}

func (s *Server) refresher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.rq:
			s.forwardMessageAndCacheResponse(q)
		}
	}
}

func (s *Server) timer(ctx context.Context) {
	t := time.NewTicker(timerResolution)
	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case t := <-t.C:
			s.mu.Lock()
			s.currentTime = t
			s.mu.Unlock()
		}
	}
}

func (s *Server) now() time.Time {
	s.mu.RLock()
	t := s.currentTime
	s.mu.RUnlock()
	return t
}

func (s *Server) forwardMessageAndCacheResponse(q *dns.Msg) (m *dns.Msg) {
	for c := 0; m == nil && c < connectionsPerUpstream; c++ {
		log.Tracef("(Re)trying %q [%d/%d]...", q.Question, c+1, connectionsPerUpstream)
		m = s.forwardMessageAndGetResponse(q)
		if m != nil {
			break
		}
	}
	if m == nil {
		log.Debugf("Giving up on %q after %d connection retries.", q.Question, connectionsPerUpstream)
		return nil
	}
	s.cache.put(q, m)
	return m
}

func (s *Server) forwardMessageAndGetResponse(q *dns.Msg) (m *dns.Msg) {
	for _, p := range s.upstreams {
		//log.Println("Request taking place...")
		r, err := (*p).Exchange(q)
		//log.Println(q.String())
		if err != nil || r == nil {
			log.WithError(err).Info("error during exchange")
			//fps.Incr(1)
			continue
		}
		if r != nil && r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
			qps.Incr(1)
			return r
		} else {
			fps.Incr(1)
			log.Infof("%q", q.String())
			log.Infof("%q", r.String())
		}
	}
	return nil
}

var errNilResponse = errors.New("nil response from upstream")
