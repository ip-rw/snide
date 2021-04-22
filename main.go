package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/ip-rw/snide/proxy"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime/debug"
	"strings"
)

var (
	upstreamServers = flag.String("s", "https://www.cloudflare-dns.com/dns-query@cloudflare.txt", "comma-separated list of upstream servers")
	logPath         = flag.String("l", "", "log file path")
	isLogVerbose    = flag.Bool("v", false, "verbose mode")
	evictMetrics    = flag.Bool("em", false, "collect metrics on evictions")
	addr            = flag.String("a", ":53", "the `address:port` to listen on. In order to listen on the loopback interface only, use `127.0.0.1:53`. To listen on any interface, use `:53`")
	ppr             = flag.Int("pprof", 0, "The port to use for pprof debugging. If set to 0 (default) pprof will not be started.")
)

func main() {
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		PadLevelText:           true,
		TimestampFormat:        "2006-01-02 15:04:05",
	})

	log.SetLevel(log.InfoLevel)
	if *isLogVerbose {
		log.SetLevel(log.DebugLevel)
	}

	if *logPath != "" {
		lf, err := os.OpenFile(*logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Errorf("Unable to open log file for writing: %s", err)
		} else {
			log.SetOutput(io.MultiWriter(lf, os.Stdout))
		}
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		log.Infof("%s v%s", path.Base(bi.Path), bi.Main.Version)
	}

	sigs := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-sigs
		cancel()
	}()
	// Run the server with a default cache size and the specified upstream servers.
	server := proxy.NewServer(10000, strings.Split(*upstreamServers, ",")...)

	if *ppr != 0 {
		go func() { log.Error(http.ListenAndServe(fmt.Sprintf("localhost:%d", *ppr), nil)) }()
	}

	log.Fatal(server.Run(ctx, *addr))
}
