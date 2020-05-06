# HoneyPot Exporter

[![Go Report Card](https://goreportcard.com/badge/github.com/intrinsec/honeypot_exporter)](https://goreportcard.com/report/github.com/intrinsec/honeypot_exporter)

Prometheus honeypot exporter

This minimal honeypot listen on networks and count each new connection or packet(for UDP),
for TCP, the connection is closed immediately after the accept.

## Building and running

### Build

```shell
make
```

### Capabilities

`honeypot_exporter` will need CAP_NET_BIND_SERVICE capability to listen on privileged ports.

### Configuration

Define listeners in the yaml config file :

```yaml
listeners:
  - network: tcp
    address: ":4242"
  - network: udp
    address: ":4242"
```

* network must be in `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`
* address follow the format `bind_ip:port`, to listen on any ipv4/6 leave bind_ip empty.

### Running

```shell
./honeypot_exporter <flags>
```

### Using Docker

```shell
docker rm -f honeypot-exporter
docker run -d \
  --name="honeypot-exporter" \
  --net="host" \
  --restart="unless-stopped" \
  --log-driver json-file --log-opt max-size=10m \
  -v $(pwd)/honeypot.yml:/honeypot.yml \
  intrinsec/honeypot-exporter-linux-amd64:v0.1.0 \
  --honeypot.config=/honeypot.yml
```

### Metrics

```text
...
# HELP honeypot_connections_total honeypot number of new connections or udp packets
# TYPE honeypot_connections_total counter
honeypot_connections_total{dst="127.0.0.1",port="4242",proto="tcp",src="127.0.0.1"} 2
honeypot_connections_total{dst="[::1]",port="4242",proto="tcp",src="[::1]"} 1
honeypot_connections_total{dst="[::]",port="4242",proto="udp",src="[::1]"} 13
...
```
