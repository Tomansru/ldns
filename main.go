package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

type (
	Cnf struct {
		Dns  CnfDns  `yaml:"dns"`
		Http CnfHttp `yaml:"http"`
	}
	CnfDns struct {
		Address   string            `yaml:"address"`   // Address with port for DNS listener
		Type      string            `yaml:"type"`      // "tcp" or "tcp-tls" (DNS over TLS) or "udp" (default)
		Ttl       int               `yaml:"ttl"`       // ttl for all custom DNS responses
		RelayAddr string            `yaml:"relayAddr"` // upstream DNS address to relay any other queries
		RelayType string            `yaml:"relayType"` // like Type for RelayAddr
		DnsList   map[string]string `yaml:"dns"`       // map with dns aliases
	}
	CnfHttp struct {
		Address string            `yaml:"address"`
		Ip      []string          `yaml:"ip"`
		Bridges []*netlink.Bridge `yaml:"-"`
	}
)

type Hl struct {
	logger    *zap.Logger
	dnsClient *dns.Client
	config    *Cnf
}

func main() {
	loggerConfig := zap.NewDevelopmentConfig()
	loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	logger, err := loggerConfig.Build()
	if err != nil {
		panic(fmt.Errorf("can't build zap logger: %w", err))
	}
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	var cnf Cnf
	var f *os.File
	if f, err = os.OpenFile("dns.yaml", os.O_RDONLY, 0666); err != nil {
		logger.Info("no such file or bad permissions dns.yaml", zap.Error(err))
		return
	}

	if err = yaml.NewDecoder(f).Decode(&cnf); err != nil {
		logger.Info("bad config file dns.yaml", zap.Error(err))
		return
	}

	hl := &Hl{
		logger: logger,
		config: &cnf,
		dnsClient: &dns.Client{
			Net: cnf.Dns.RelayType,
		},
	}

	var wg = sync.WaitGroup{}
	wg.Add(1) // 1 for exiting on a single error

	go func() {
		logger.Info(fmt.Sprintf("Start DNS Server on address %s with listner type %s", hl.config.Dns.Address, hl.config.Dns.Type))
		if err = dns.ListenAndServe(hl.config.Dns.Address, hl.config.Dns.Type, hl); err != nil {
			logger.Error("Error dns.ListenAndServe", zap.Error(err))
		}
		wg.Done()
	}()

	var br *netlink.Bridge
	hl.config.Http.Bridges = make([]*netlink.Bridge, 0, len(hl.config.Http.Ip))
	for i, v := range hl.config.Http.Ip {
		li := netlink.NewLinkAttrs()
		li.Name = "ldns" + strconv.Itoa(i+1)
		br = &netlink.Bridge{LinkAttrs: li}
		if err = netlink.LinkAdd(br); err != nil {
			logger.Error("Error netlink.LinkAdd", zap.Error(err))
		}

		var addr *netlink.Addr
		if addr, err = netlink.ParseAddr(v); err != nil {
			logger.Error("Error netlink.ParseAddr", zap.Error(err))
		}

		if err = netlink.AddrAdd(br, addr); err != nil {
			logger.Error("Error netlink.AddrAdd", zap.Error(err))
		}

		hl.config.Http.Bridges = append(hl.config.Http.Bridges, br)
	}

	defer func() {
		for _, v := range hl.config.Http.Bridges {
			if err = netlink.LinkDel(v); err != nil {
				logger.Error("Error netlink.LinkDel", zap.Error(err))
			}
		}
	}()

	wg.Wait()
}

func (h *Hl) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// github.com/miekg/dns/types.go:223 Usually there is just one. While the
	// original DNS RFCs allow multiple questions in the question section of a
	// message, in practice it never works. Because most DNS servers see multiple
	// questions as an error.
	q := r.Question[0]

	ip, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	logger := h.logger.With(
		zap.String("ip", ip),
		zap.String("domain", q.Name),
		zap.String("raw_req", strings.ReplaceAll(q.String(), "\t", "")))

	var err error
	var m *dns.Msg
	switch val, ok := h.config.Dns.DnsList[q.Name]; true {
	case q.Qtype == dns.TypeA && ok:
		m = &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Authoritative: true,
			},
			Answer: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: q.Qtype,
					Class:  q.Qclass,
					Ttl:    uint32(h.config.Dns.Ttl),
				},
				A: net.ParseIP(val),
			}},
		}
	default:
		m, _, err = h.dnsClient.Exchange(r, h.config.Dns.RelayAddr)
		if err != nil {
			logger.Error("Client exchange error", zap.Error(err))
		}
	}

	m.SetReply(r)
	if err = w.WriteMsg(m); err != nil {
		logger.Error("Write response error", zap.Error(err))
	}

	var val string
	if m.Answer != nil && len(m.Answer[0].String()) > 0 {
		val = strings.ReplaceAll(m.Answer[0].String(), "\t", " ")
	}
	logger.Debug("DNS resolved", zap.String("raw_res", val))
}
