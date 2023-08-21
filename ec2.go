package ec2

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type Map struct {
	name4 map[string][]net.IP
	addr  map[string][]string
}

func newMap() *Map {
	return &Map{
		name4: make(map[string][]net.IP),
		addr:  make(map[string][]string),
	}
}

type EC2 struct {
	sync.RWMutex

	Next plugin.Handler
	Fall fall.F

	origins []string
	hmap    *Map
	ttl     uint32
	reload  time.Duration

	credentials aws.Credentials
	endpoint    string
	region      string
}

func (e *EC2) Name() string {
	return "ec2"
}

func (e *EC2) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	var answers []dns.RR

	zone := plugin.Zones(e.origins).Matches(qname)
	if zone == "" {
		if state.QType() != dns.TypePTR {
			return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
		}
	}

	switch state.QType() {
	case dns.TypePTR:
		names := e.LookupAddr(dnsutil.ExtractAddressFromReverse(qname))
		if len(names) == 0 {
			return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
		}
		answers = ptr(qname, e.ttl, names)
	case dns.TypeA:
		ips := e.lookupHostV4(qname)
		answers = a(qname, e.ttl, ips)
	}

	if len(answers) == 0 {
		if e.Fall.Through(qname) {
			return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
		}

		return dns.RcodeServerFailure, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers

	if err := w.WriteMsg(m); err != nil {
		log.Error(err)
	}

	return dns.RcodeSuccess, nil
}

func (e *EC2) updateMap() {
	log.Debugf("Updating server list")
	hmap := newMap()

	client := ec2.NewFromConfig(aws.Config{
		Credentials: credentials.NewStaticCredentialsProvider(e.credentials.AccessKeyID, e.credentials.SecretAccessKey, ""),
		Region:      e.region,
	}, func(o *ec2.Options) {
		if e.endpoint != "" {
			o.EndpointResolver = ec2.EndpointResolverFromURL(e.endpoint)

		}
	})

	result, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
	if err != nil {
		log.Errorf("Failed to fetch instances: %s", err)
		return
	}

	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			var fqdnTag string
			var nameTag string

			for _, tag := range instance.Tags {
				switch *tag.Key {
				case "Name":
					nameTag = *tag.Value
				case "FQDN":
					fqdnTag = *tag.Value
				}
			}

			for _, zone := range e.origins {
				var name4 string

				if fqdnTag != "" {
					fqdnTag = fqdnTag + "."
					if strings.HasSuffix(fqdnTag, zone) {
						name4 = fqdnTag
					}
				}

				if name4 == "" && nameTag != "" {
					name4 = dnsutil.Join(nameTag, zone)
				}

				if name4 == "" {
					name4 = dnsutil.Join(*instance.InstanceId, zone)
				}

				addr := net.ParseIP(*instance.PrivateIpAddress)
				hmap.name4[name4] = append(hmap.name4[name4], addr)
				hmap.addr[addr.String()] = append(hmap.addr[addr.String()], name4)
			}
		}
	}

	e.Lock()
	e.hmap = hmap
	e.Unlock()
}

func (e *EC2) lookupHostV4(host string) []net.IP {
	e.RLock()
	defer e.RUnlock()

	ips, ok := e.hmap.name4[host]
	if !ok {
		return nil
	}

	ipsCp := make([]net.IP, len(ips))
	copy(ipsCp, ips)
	return ipsCp
}

func (e *EC2) LookupAddr(addr string) []string {
	addr = net.ParseIP(addr).String()
	if addr == "" {
		return nil
	}

	e.RLock()
	defer e.RUnlock()
	hosts := e.hmap.addr[addr]

	if len(hosts) == 0 {
		return nil
	}

	hostsCp := make([]string, len(hosts))
	copy(hostsCp, hosts)
	return hostsCp
}

func a(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
		r.A = ip
		answers[i] = r
	}
	return answers
}

func ptr(zone string, ttl uint32, names []string) []dns.RR {
	answers := make([]dns.RR, len(names))
	for i, n := range names {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.Ptr = dns.Fqdn(n)
		answers[i] = r
	}
	return answers
}
