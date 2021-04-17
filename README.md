# snide

dns-over-https seems to have everybody very excited. Cloudflare runs a free DoH service alongside its vast
network of what are effectively reverse (SNI) proxies. We can take advantage of this situation to avoid rate limiting and
end up with a high quality, fast (10k+ qps) DNS resolver.

this is actually a fork of https://github.com/mikispag/dns-over-tls-forwarder. i've had to make some changes to 'upstream' 
in https://github.com/AdguardTeam/dnsproxy in order to have each resolver entry take a filename instead of a single ip.

many thanks to both projects, all credit goes to them. the upstream stuff in dnsproxy is brilliant, as is the highly optimized sever in the project by mikispag.

```
Usage of /tmp/go-build2261890375/b001/exe/main:
  -a address:port
        the address:port to listen on. In order to listen on the loopback interface only, use `127.0.0.1:53`. To listen on any interface, use `:53` (default ":53")
  -em
        collect metrics on evictions
  -l string
        log file path
  -pprof int
        The port to use for pprof debugging. If set to 0 (default) pprof will not be started.
  -s string
        comma-separated list of upstream servers (default "https://www.cloudflare-dns.com/dns-query@cloudflare.txt")
  -v    verbose mode
```

### anecdotal evidence (dnssearch with 600 workers)
```
Requests : 2171687
Results  : 1406
Time     : 103.192774132 s
Req/s    : 21044.952209755174
```

There is still something rattling around broken in here...