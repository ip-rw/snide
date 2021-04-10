# snide

dns-over-https seems to have everybody very excited. Cloudflare runs a free DoH service, alongside its vast
network of what are effectively reverse (SNI) proxies. We can take advantage of this situation to avoid rate limiting and 
end up with a high quality, fast (10k qps) DNS resolver.

This is a simple DNS to DoH proxy. There are plenty of feature-full DoH proxies out there but none of them made it easy 
to specify our CDN IPs. 

```
Usage of /tmp/go-build3029987891/b001/exe/main:
  -addr string
        file containing cdn ips to query (default "cloudflare.txt")
  -port int
        port to run on (default 53)
  -url string
        doh provider url (default "https://cloudflare-dns.com/dns-query")
  -v    verbose

```

Bizarrely 