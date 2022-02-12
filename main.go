package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/valyala/fasthttp"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

type (
	Cnf struct {
		Dns   CnfDns  `yaml:"dns"`
		Http  CnfHttp `yaml:"http"`
		Https CnfHttp `yaml:"https"`
		Eth   CnfEth  `yaml:"eth"`
	}
	CnfDns struct {
		Address   string            `yaml:"address"`   // Address with port for DNS listener
		Type      string            `yaml:"type"`      // "tcp" or "tcp-tls" (DNS over TLS) or "udp" (default)
		Ttl       int               `yaml:"ttl"`       // ttl for all custom DNS responses
		RelayAddr string            `yaml:"relayAddr"` // upstream DNS address to relay any other queries
		RelayType string            `yaml:"relayType"` // like Type for RelayAddr
		DefaultIp string            `yaml:"defaultIp"` // use like value in DnsList if val == ""
		DnsList   map[string]string `yaml:"dns"`       // map with dns aliases
	}
	CnfHttp struct {
		Address string `yaml:"address"` // Address with port for HTTP listener
		CaCert  string `yaml:"caCert"`
		CaKey   string `yaml:"caKey"`
	}
	CnfEth struct {
		Out     []string                    `yaml:"out"`
		Bridges []*netlink.Bridge           `yaml:"-"`
		Clients map[string]*fasthttp.Client `yaml:"-"`
	}
)

type Hl struct {
	logger    *zap.Logger
	dnsClient *dns.Client
	config    *Cnf
}

func main() {
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	logger, err := loggerConfig.Build()
	if err != nil {
		panic(fmt.Errorf("can't build zap logger: %w", err))
	}
	defer logger.Sync()
	zap.ReplaceGlobals(logger)

	f, err := os.OpenFile("dns.yaml", os.O_RDONLY, 0666)
	if err != nil {
		logger.Info("no such file or bad permissions dns.yaml", zap.Error(err))
		os.Exit(1)
	}

	var cnf Cnf
	err = yaml.NewDecoder(f).Decode(&cnf)
	if err != nil {
		logger.Info("bad config file dns.yaml", zap.Error(err))
		os.Exit(1)
	}
	_ = f.Close()

	hl := &Hl{
		logger: logger,
		config: &cnf,
		dnsClient: &dns.Client{
			Net: cnf.Dns.RelayType,
		},
	}

	var addrs map[string]*net.TCPAddr
	cnf.Eth.Bridges, addrs, err = BindBridger(cnf.Eth.Out)
	if err != nil {
		logger.Error("Error BindBridger", zap.Error(err))
		os.Exit(1)
	}

	cnf.Eth.Clients, err = BuildHttpClient(addrs)
	if err != nil {
		logger.Error("Error BuildHttpClient", zap.Error(err))
		os.Exit(1)
	}

	hosts := make([]string, 0, len(cnf.Dns.DnsList))
	domains := make(map[string]string, len(cnf.Dns.DnsList))
	for k, v := range cnf.Dns.DnsList {
		hosts = append(hosts, k)
		if v == "" {
			v = cnf.Dns.DefaultIp
		}
		domains[dns.CanonicalName(k)] = v
	}
	cnf.Dns.DnsList = domains

	cert, priv, err := hl.GenerateTestCertificate(hosts)
	if err != nil {
		logger.Error("Error hl.GenerateTestCertificate", zap.Error(err))
		os.Exit(1)
	}

	defer func() {
		if r := recover(); r != nil {
			for _, v := range cnf.Eth.Bridges {
				if err = netlink.LinkDel(v); err != nil {
					logger.Error("Error netlink.LinkDel", zap.Error(err))
				}
			}
			logger.Panic("Panic", zap.Any("panic", r))
			os.Exit(1)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		exitCode := 0
		for range c {
			for _, v := range cnf.Eth.Bridges {
				if err = netlink.LinkDel(v); err != nil {
					logger.Error("Error netlink.LinkDel", zap.Error(err))
					exitCode = 1
				}
			}
			os.Exit(exitCode)
		}
	}()

	var wg = sync.WaitGroup{}
	wg.Add(1) // 1 for exiting on a single error

	go func() {
		logger.Info(fmt.Sprintf("Start DNS Server on address %s with listner type %s", cnf.Dns.Address, cnf.Dns.Type))
		if err = dns.ListenAndServe(cnf.Dns.Address, cnf.Dns.Type, hl); err != nil {
			logger.Error("Error dns.ListenAndServe", zap.Error(err))
			os.Exit(1)
		}
		wg.Done()
	}()

	go func() {
		logger.Info(fmt.Sprintf("Start HTTP Server on address %s", cnf.Http.Address))
		if err = fasthttp.ListenAndServe(cnf.Http.Address, hl.ServeHTTP); err != nil {
			logger.Error("Error dns.ListenAndServe", zap.Error(err))
			os.Exit(1)
		}
		wg.Done()
	}()

	go func() {
		logger.Info(fmt.Sprintf("Start HTTPS Server on address %s", cnf.Https.Address))
		if err = fasthttp.ListenAndServeTLSEmbed(cnf.Https.Address, cert, priv, hl.ServeHTTP); err != nil {
			logger.Error("Error dns.ListenAndServe", zap.Error(err))
			os.Exit(1)
		}
		wg.Done()
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
		zap.String("domain", q.Name))
	//zap.String("raw_req", strings.ReplaceAll(q.String(), "\t", "")))

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
		switch {
		case err == nil:
			// pass
		case errors.Is(err, context.DeadlineExceeded):
			logger.Debug("Context deadline", zap.Error(err))
			return
		case errors.Is(err, syscall.ECONNRESET):
			logger.Debug("Connection reset by peer", zap.Error(err))
			return
		default:
			logger.Error("Client exchange error", zap.Error(err))
			panic(err) // for dev
		}
	}

	m.SetReply(r)
	if err = w.WriteMsg(m); err != nil {
		logger.Error("Write response error", zap.Error(err))
	}

	//var val string
	//if m.Answer != nil && len(m.Answer[0].String()) > 0 {
	//	val = strings.ReplaceAll(m.Answer[0].String(), "\t", " ")
	//}
	//logger.Debug("DNS resolved", zap.String("raw_res", val))
	logger.Debug("DNS resolved")
}

func (h *Hl) ServeHTTP(ctx *fasthttp.RequestCtx) {
	logger := h.logger.With(
		zap.String("ip", ctx.RemoteAddr().String()),
		zap.String("domain", string(ctx.Host())),
		zap.String("path", string(ctx.Path())))

	req := &ctx.Request
	resp := &ctx.Response
	prepareRequest(req)
	if err := proxyClient.Do(req, resp); err != nil {
		logger.Error("Write proxyClient.Do error", zap.Error(err))
		panic(err) // for dev
	}
	postprocessResponse(resp)

	logger.Debug("HTTP Pass")
}

func NewHttpClient(addr *net.TCPAddr) *fasthttp.Client {
	return &fasthttp.Client{
		Dial: (&fasthttp.TCPDialer{
			LocalAddr: addr,
		}).Dial,
	}
}

var proxyClient = &fasthttp.Client{}

func prepareRequest(req *fasthttp.Request) {
	req.Header.Del("Connection")
}

func postprocessResponse(resp *fasthttp.Response) {
	resp.Header.Del("Connection")
}

// GenerateTestCertificate generates a certificate and private key based on the given host.
func (h *Hl) GenerateTestCertificate(hosts []string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.SHA256WithRSA,

		Subject: pkix.Name{
			Country:      []string{"RU"},
			Locality:     []string{"St. Petersburg"},
			Organization: []string{"Tomansru"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		//BasicConstraintsValid: true,
		//IsCA:                  true,

		DNSNames: hosts,
	}

	ccc, err := tls.LoadX509KeyPair(h.config.Https.CaCert, h.config.Https.CaKey)
	x509Cert, err := x509.ParseCertificate(ccc.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, x509Cert, &priv.PublicKey, ccc.PrivateKey)

	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	b := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		},
	)

	return b, p, err
}

// BindBridger create net interface and bind address
func BindBridger(hosts []string) ([]*netlink.Bridge, map[string]*net.TCPAddr, error) {
	addrs := make(map[string]*net.TCPAddr, len(hosts))
	brs := make([]*netlink.Bridge, 0, len(hosts))
	for i, v := range hosts {
		li := netlink.NewLinkAttrs()
		li.Name = "ldns" + strconv.Itoa(i)

		br := &netlink.Bridge{LinkAttrs: li}

		err := netlink.LinkAdd(br)
		if err != nil {
			return nil, nil, fmt.Errorf("error netlink.LinkAdd: %w", err)
		}

		addr, err := netlink.ParseAddr(v)
		if err != nil {
			return nil, nil, fmt.Errorf("error netlink.ParseAddr: %w", err)

		}

		err = netlink.AddrAdd(br, addr)
		if err != nil {
			return nil, nil, fmt.Errorf("error netlink.AddrAdd: %w", err)
		}

		ad, err := net.ResolveTCPAddr("tcp", addr.IPNet.IP.String()+":0")
		if err != nil {
			return nil, nil, fmt.Errorf("error net.ResolveTCPAddr: %w", err)
		}

		addrs[v] = ad
		brs = append(brs, br)
	}

	return brs, addrs, nil
}

func BuildHttpClient(addrs map[string]*net.TCPAddr) (map[string]*fasthttp.Client, error) {
	cls := make(map[string]*fasthttp.Client, len(addrs))
	for k, v := range addrs {
		cls[k] = NewHttpClient(v)
	}
	return cls, nil
}
