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
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type labels struct {
	proto string
	src   string
	dst   string
	port  string
}

type honeypotCollector struct {
	current typedDesc
	logger  log.Logger
	config  Config
	metrics map[labels]uint64
}

func init() {
	registerCollector("honeypot", defaultEnabled, NewHoneyPotCollector)
}

// NewHoneyPotCollector returns a new Collector exposing honeypot metrics.
func NewHoneyPotCollector(logger log.Logger, config Config) (Collector, error) {

	hc := &honeypotCollector{
		current: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "connections_total"),
			"honeypot number of new connections or udp packets",
			[]string{"proto", "src", "dst", "port"}, nil,
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
		ch <- c.current.mustNewConstMetric(float64(v), k.proto, k.src, k.dst, k.port)
	}

	return nil
}

type connEvent struct {
	local  net.Addr
	remote net.Addr
}

func Listener(network, address string, res chan<- connEvent, logger log.Logger) {

	if strings.HasPrefix(network, "tcp") {
		l, err := net.Listen(network, address)
		if err != nil {

			return
		}
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				level.Error(logger).Log("network", network, "address", address, "err", err)
				continue
			}
			res <- connEvent{c.LocalAddr(), c.RemoteAddr()}
			c.Close()
		}
	} else {
		l, err := net.ListenPacket(network, address)
		if err != nil {
			level.Error(logger).Log("network", network, "address", address, "err", err)
			return
		}
		buf := make([]byte, 1)
		defer l.Close()
		for {

			_, addr, err := l.ReadFrom(buf)
			if err != nil {
				level.Error(logger).Log("network", network, "address", address, "err", err)
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

	for _, listener := range c.config.Listeners {
		level.Info(c.logger).Log(
			"msg", "new listener",
			"network", listener.Network,
			"address", listener.Address,
		)
		go Listener(listener.Network, listener.Address, results, c.logger)
	}

	go func() {
		for {
			r := <-results
			src, _ := AddrSplit(r.remote)
			dst, port := AddrSplit(r.local)

			key := labels{
				proto: r.local.Network(),
				src:   src,
				dst:   dst,
				port:  port,
			}
			if val, ok := c.metrics[key]; ok {
				c.metrics[key] = val + 1
			} else {
				c.metrics[key] = 1
			}
			level.Debug(c.logger).Log("rx", key)
		}
	}()
}
