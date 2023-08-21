package ec2

import (
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("ec2")

func init() { plugin.Register("ec2", setup) }

func periodicUpdateMap(e *EC2) chan bool {
	updateChan := make(chan bool)

	if e.reload == 0 {
		return updateChan
	}

	go func() {
		ticker := time.NewTicker(e.reload)
		for {
			select {
			case <-updateChan:
				return
			case <-ticker.C:
				e.updateMap()
			}
		}
	}()

	return updateChan
}

func setup(c *caddy.Controller) error {
	os, err := ec2Parse(c)
	if err != nil {
		return plugin.Error("ec2", err)
	}

	updateChan := periodicUpdateMap(os)

	c.OnStartup(func() error {
		os.updateMap()
		return nil
	})

	c.OnShutdown(func() error {
		close(updateChan)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		os.Next = next
		return os
	})

	return nil
}

func ec2Parse(c *caddy.Controller) (*EC2, error) {
	ec2 := EC2{
		hmap:        newMap(),
		credentials: aws.Credentials{},
		ttl:         3600,
		reload:      30 * time.Second,
	}

	i := 0
	for c.Next() {
		if i > 0 {
			return &ec2, plugin.ErrOnce
		}
		i++

		ec2.origins = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

		for c.NextBlock() {
			switch c.Val() {
			case "endpoint":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ec2.endpoint = args[0]
			case "access_key_id":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ec2.credentials.AccessKeyID = args[0]
			case "secret_key":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ec2.credentials.SecretAccessKey = args[0]
			case "region":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ec2.region = args[0]
			case "ttl":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				ttl, err := strconv.Atoi(args[0])
				if err != nil {
					return nil, c.Errf("ttl needs a number of second")
				}
				if ttl <= 0 || ttl > 65535 {
					return nil, c.Errf("ttl provided is invalid")
				}
				ec2.ttl = uint32(ttl)
			case "reload":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return nil, c.ArgErr()
				}
				reload, err := time.ParseDuration(args[0])
				if err != nil {
					return nil, c.Errf("invalid duration for reload '%s'", args[0])
				}
				if reload < 0 {
					return nil, c.Errf("invalid negative duration for reload '%s'", args[0])
				}
				ec2.reload = reload
			case "fallthrough":
				ec2.Fall.SetZonesFromArgs(c.RemainingArgs())
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	return &ec2, nil
}
