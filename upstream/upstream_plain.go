package upstream

import (
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

//
// plain DNS
//
type plainDNS struct {
	address   string
	timeout   time.Duration
	preferTCP bool
}

// Address returns the original address that we've put in initially, not resolved one
func (p *plainDNS) Address() string {
	if p.preferTCP {
		return "tcp://" + p.address
	}
	return p.address
}

func (p *plainDNS) Exchange(m *dns.Msg) (*dns.Msg, error) {
	if p.preferTCP {
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}
		logBegin(p.Address(), m)
		reply, _, tcpErr := tcpClient.Exchange(m, p.address)
		logFinish(p.Address(), tcpErr)
		return reply, tcpErr
	}

	client := dns.Client{Timeout: p.timeout, UDPSize: dns.MaxMsgSize}

	logBegin(p.Address(), m)
	reply, _, err := client.Exchange(m, p.address)
	logFinish(p.Address(), err)

	if reply != nil && reply.Truncated {
		log.Tracef("Truncated message was received, retrying over TCP, question: %s", m.Question[0].String())
		tcpClient := dns.Client{Net: "tcp", Timeout: p.timeout}
		logBegin(p.Address(), m)
		reply, _, err = tcpClient.Exchange(m, p.address)
		logFinish(p.Address(), err)
	}

	return reply, err
}
