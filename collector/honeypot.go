// Copyright 2020 Intrinsec
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !nohoneypot

package collector

import (
	"net"
	"strconv"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type labels struct {
	auth  bool
	proto string
	dst   string
	port  string
}

type honeypotCollector struct {
	authorized   typedDesc
	unauthorized typedDesc
	logger       log.Logger
	config       Config
	metrics      map[labels]uint64
}

func init() {
	registerCollector("honeypot", defaultEnabled, NewHoneyPotCollector)
}

// NewHoneyPotCollector returns a new Collector exposing honeypot metrics.
func NewHoneyPotCollector(logger log.Logger, config Config) (Collector, error) {

	hc := &honeypotCollector{
		authorized: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "authorized_connections_total"),
			"honeypot number of new authorized connections or udp packets",
			[]string{"proto", "dst", "port"}, nil,
		), prometheus.CounterValue},
		unauthorized: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "unauthorized_connections_total"),
			"honeypot number of new unauthorized connections or udp packets",
			[]string{"proto", "dst", "port"}, nil,
		), prometheus.CounterValue},
		logger:  logger,
		config:  config,
		metrics: make(map[labels]uint64),
	}

	hc.startListeners()

	return hc, nil
}

func (c *honeypotCollector) Update(ch chan<- prometheus.Metric) (err error) {

	for k, v := range c.metrics {
		if k.auth {
			ch <- c.authorized.mustNewConstMetric(float64(v), k.proto, k.dst, k.port)
		} else {
			ch <- c.unauthorized.mustNewConstMetric(float64(v), k.proto, k.dst, k.port)
		}
	}

	return nil
}

type connEvent struct {
	local  net.Addr
	remote net.Addr
}

func Listener(protocol, address string, res chan<- connEvent, logger log.Logger) {

	if strings.HasPrefix(protocol, "tcp") {
		l, err := net.Listen(protocol, address)
		if err != nil {

			return
		}
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				level.Error(logger).Log("protocol", protocol, "address", address, "err", err)
				continue
			}
			res <- connEvent{c.LocalAddr(), c.RemoteAddr()}
			c.Close()
		}
	} else {
		l, err := net.ListenPacket(protocol, address)
		if err != nil {
			level.Error(logger).Log("protocol", protocol, "address", address, "err", err)
			return
		}
		buf := make([]byte, 1)
		defer l.Close()
		for {

			_, addr, err := l.ReadFrom(buf)
			if err != nil {
				level.Error(logger).Log("protocol", protocol, "address", address, "err", err)
				continue
			}
			res <- connEvent{l.LocalAddr(), addr}

		}
	}
}

func AddrSplit(addr net.Addr) (string, string) {
	slice := strings.Split(addr.String(), ":")
	if len(slice) <= 1 {
		return "", ""
	}
	return strings.Join(slice[:len(slice)-1], ":"), slice[len(slice)-1]
}

func (c *honeypotCollector) startListeners() {

	results := make(chan connEvent, 100)
	var ListenersAuthorized = make(map[string][]*net.IPNet)

	for _, listener := range c.config.Listeners {
		level.Info(c.logger).Log(
			"msg", "new listener",
			"protocol", listener.Protocol,
			"address", listener.Address,
		)
		var key = listener.Protocol + listener.Address
		ListenersAuthorized[key] = append(c.config.GlobalAuthorized, listener.Authorized...)
		go Listener(listener.Protocol, listener.Address, results, c.logger)
	}

	go func() {
		for {
			r := <-results
			src, _ := AddrSplit(r.remote)
			dst, port := AddrSplit(r.local)
			proto := r.local.Network()

			ipSrc := net.ParseIP(src)

			var key = proto + ":" + port
			networks := ListenersAuthorized[key]

			auth := false
			for _, netw := range networks {
				if netw.Contains(ipSrc) {
					auth = true
				}
			}
			level.Info(c.logger).Log(
				"msg", "new connection",
				"authorized", strconv.FormatBool(auth),
				"protocol", proto,
				"port", port,
				"source", src,
				"destination", dst,
			)

			lab := labels{
				auth:  auth,
				proto: proto,
				dst:   dst,
				port:  port,
			}
			if val, ok := c.metrics[lab]; ok {
				c.metrics[lab] = val + 1
			} else {
				c.metrics[lab] = 1
			}
			level.Debug(c.logger).Log("rx", key)
		}
	}()
}
