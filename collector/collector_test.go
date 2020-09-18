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
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"path/filepath"
	"testing"
)

func TestStrToIPNet(t *testing.T) {

	TestItems := []string{
		"1.2.3.4",
		"1.2.3.4/32",
	}

	for i, item := range TestItems {
		ipnet, err := StrToIPNet(item)
		assert.Nil(t, err, fmt.Sprintf("error on item number %d", i))
		assert.IsType(t, &net.IPNet{}, ipnet, fmt.Sprintf("item number %d", i))
	}

}

func TestParseConfig(t *testing.T) {
	path := filepath.Join("testdata", "honeypot.yml")
	config, err := ParseConfig(path)
	assert.Nil(t, err, "error on parsing configuration")
	assert.IsType(t, Config{}, config, fmt.Sprintf("config is type %T", config))
	lenGlobal := len(config.GlobalAuthorized)
	assert.Equal(t, lenGlobal, 2, fmt.Sprintf("global authorized is len %d", lenGlobal))
	lenListeners := len(config.Listeners)
	assert.Equal(t, lenListeners, 3, fmt.Sprintf("listeners is len %d", lenListeners))
}

//Mock a net.Addr interface
type Addr struct {
	host string
}

func (a Addr) String() string {
	return a.host
}
func (a Addr) Network() string {
	return ""
}

func TestAddrSplit(t *testing.T) {

	type TestItem struct {
		addr net.Addr
		host string
		port string
	}
	TestItems := []TestItem{
		{Addr{"1.2.3.4:80"}, "1.2.3.4", "80"},
		{Addr{"1.2.3.4:"}, "1.2.3.4", ""},
		{Addr{"1.2.3.4"}, "", ""},
	}

	for i, item := range TestItems {
		host, port := AddrSplit(item.addr)
		assert.Equal(t, item.host, host, fmt.Sprintf("host of item number %d", i))
		assert.Equal(t, item.port, port, fmt.Sprintf("port of item number %d", i))
	}

}
