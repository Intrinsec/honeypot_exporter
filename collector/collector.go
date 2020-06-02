// Copyright 2015 The Prometheus Authors
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

// Package collector includes all individual collectors to gather and export system metrics.
package collector

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

// Namespace defines the common namespace to be used by all metrics.
const namespace = "honeypot"

var (
	scrapeDurationDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "scrape", "collector_duration_seconds"),
		"honeypot_exporter: Duration of a collector scrape.",
		[]string{"collector"},
		nil,
	)
	scrapeSuccessDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "scrape", "collector_success"),
		"honeypot_exporter: Whether a collector succeeded.",
		[]string{"collector"},
		nil,
	)
)

const (
	defaultEnabled = true
	//defaultDisabled = false
)

var (
	factories        = make(map[string]func(logger log.Logger, config Config) (Collector, error))
	collectorState   = make(map[string]*bool)
	forcedCollectors = map[string]bool{} // collectors which have been explicitly enabled or disabled
)

func registerCollector(
	collector string,
	isDefaultEnabled bool,
	factory func(logger log.Logger, config Config) (Collector, error),
) {
	var helpDefaultState string
	if isDefaultEnabled {
		helpDefaultState = "enabled"
	} else {
		helpDefaultState = "disabled"
	}

	flagName := fmt.Sprintf("collector.%s", collector)
	flagHelp := fmt.Sprintf("Enable the %s collector (default: %s).", collector, helpDefaultState)
	defaultValue := fmt.Sprintf("%v", isDefaultEnabled)

	flag := kingpin.Flag(flagName, flagHelp).Default(defaultValue).Action(collectorFlagAction(collector)).Bool()
	collectorState[collector] = flag

	factories[collector] = factory
}

var PROTOCOLS = map[string]bool{
	"tcp": true,
	"udp": true,
}

// MainCollector implements the prometheus.Collector interface.
type MainCollector struct {
	Collectors map[string]Collector
	logger     log.Logger
	config     Config
}

// Config and NetConfig define the Structure of the yaml configuration file.
type NetConfig struct {
	Protocol   string
	Address    string
	Authorized []*net.IPNet
}

type Config struct {
	GlobalAuthorized []*net.IPNet
	Listeners        []NetConfig
}

// Parses string into net.IPNet
// Will tranform when a single IP is given by taking the CIDR annotation with /32
func StrToIPNet(ip string) (*net.IPNet, error) {
	matched, err := regexp.MatchString(".*/[0-9]{1,2}", ip)
	if err != nil {
		return nil, err
	}
	if !matched {
		ip = ip + "/32"
	}
	_, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return nil, err
	}
	return ipnet, nil

}

// Implement the yaml.v2 unmarshalling interface (https://godoc.org/gopkg.in/yaml.v2#Unmarshaler)
// to decode the yaml file into custome types.
// Inspired from https://sharpend.io/blog/decoding-yaml-in-go/.
// Uses auxiliary struct to suport customs decoding.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {

	var aux struct {
		GlobalAuthorized []string `yaml:"authorized"`
		Listeners        []struct {
			Protocol   string   `yaml:"protocol"`
			Address    string   `yaml:"address"`
			Authorized []string `yaml:"authorized"`
		}
	}

	if err := unmarshal(&aux); err != nil {
		return err
	}

	globalAuthorized := make([]*net.IPNet, len(aux.GlobalAuthorized))
	for i, ip := range aux.GlobalAuthorized {

		ipnet, err := StrToIPNet(ip)
		if err != nil {
			return err
		}
		globalAuthorized[i] = ipnet
	}

	listeners := make([]NetConfig, len(aux.Listeners))
	for i, nc := range aux.Listeners {
		if !PROTOCOLS[nc.Protocol] {
			return fmt.Errorf("unauthorized protocol : %s", nc.Protocol)
		}

		authorized := make([]*net.IPNet, len(nc.Authorized))
		for j, ip := range nc.Authorized {
			ipnet, err := StrToIPNet(ip)
			if err != nil {
				return err
			}
			authorized[j] = ipnet
		}

		listeners[i].Protocol = nc.Protocol
		listeners[i].Address = nc.Address
		listeners[i].Authorized = authorized
	}

	c.GlobalAuthorized = globalAuthorized
	c.Listeners = listeners

	return nil

}

// Reads the yaml file and unmarshall it.
func ParseConfig(path string) (Config, error) {
	cfgFile, err := ioutil.ReadFile(path)
	cfg := Config{}
	if err != nil {
		return cfg, err
	}

	if yaml.Unmarshal([]byte(cfgFile), &cfg) != nil {
		return cfg, err
	}
	return cfg, nil
}

// DisableDefaultCollectors sets the collector state to false for all collectors which
// have not been explicitly enabled on the command line.
func DisableDefaultCollectors() {
	for c := range collectorState {
		if _, ok := forcedCollectors[c]; !ok {
			*collectorState[c] = false
		}
	}
}

// collectorFlagAction generates a new action function for the given collector
// to track whether it has been explicitly enabled or disabled from the command line.
// A new action function is needed for each collector flag because the ParseContext
// does not contain information about which flag called the action.
// See: https://github.com/alecthomas/kingpin/issues/294
func collectorFlagAction(collector string) func(ctx *kingpin.ParseContext) error {
	return func(ctx *kingpin.ParseContext) error {
		forcedCollectors[collector] = true
		return nil
	}
}

// NewMainCollector creates a new MainCollector.
func NewMainCollector(logger log.Logger, config Config, filters ...string) (*MainCollector, error) {
	f := make(map[string]bool)
	for _, filter := range filters {
		enabled, exist := collectorState[filter]
		if !exist {
			return nil, fmt.Errorf("missing collector: %s", filter)
		}
		if !*enabled {
			return nil, fmt.Errorf("disabled collector: %s", filter)
		}
		f[filter] = true
	}
	collectors := make(map[string]Collector)
	for key, enabled := range collectorState {
		if *enabled {
			collector, err := factories[key](log.With(logger, "collector", key), config)
			if err != nil {
				return nil, err
			}
			if len(f) == 0 || f[key] {
				collectors[key] = collector
			}
		}
	}
	return &MainCollector{
		Collectors: collectors,
		logger:     logger,
		config:     config,
	}, nil
}

// Describe implements the prometheus.Collector interface.
func (n MainCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- scrapeDurationDesc
	ch <- scrapeSuccessDesc
}

// Collect implements the prometheus.Collector interface.
func (n MainCollector) Collect(ch chan<- prometheus.Metric) {
	wg := sync.WaitGroup{}
	wg.Add(len(n.Collectors))
	for name, c := range n.Collectors {
		go func(name string, c Collector) {
			execute(name, c, ch, n.logger)
			wg.Done()
		}(name, c)
	}
	wg.Wait()
}

func execute(name string, c Collector, ch chan<- prometheus.Metric, logger log.Logger) {
	begin := time.Now()
	err := c.Update(ch)
	duration := time.Since(begin)
	var success float64

	if err != nil {
		if IsNoDataError(err) {
			level.Debug(logger).Log("msg", "collector returned no data", "name", name, "duration_seconds", duration.Seconds(), "err", err)
		} else {
			level.Error(logger).Log("msg", "collector failed", "name", name, "duration_seconds", duration.Seconds(), "err", err)
		}
		success = 0
	} else {
		level.Debug(logger).Log("msg", "collector succeeded", "name", name, "duration_seconds", duration.Seconds())
		success = 1
	}
	ch <- prometheus.MustNewConstMetric(scrapeDurationDesc, prometheus.GaugeValue, duration.Seconds(), name)
	ch <- prometheus.MustNewConstMetric(scrapeSuccessDesc, prometheus.GaugeValue, success, name)
}

// Collector is the interface a collector has to implement.
type Collector interface {
	// Get new metrics and expose them via prometheus registry.
	Update(ch chan<- prometheus.Metric) error
}

type typedDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

func (d *typedDesc) mustNewConstMetric(value float64, labels ...string) prometheus.Metric {
	return prometheus.MustNewConstMetric(d.desc, d.valueType, value, labels...)
}

// ErrNoData indicates the collector found no data to collect, but had no other error.
var ErrNoData = errors.New("collector returned no data")

func IsNoDataError(err error) bool {
	return err == ErrNoData
}
