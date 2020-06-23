import socket

import requests
from scapy.all import send, IP, UDP

HONEYPOT_EXPORTER_URL = "http://honeypot:9733/metrics"

# The ip of the honeypot exporter is fixed in the docker-compose
HONEYPOT_IP = "172.20.0.10"
HONEYPOT_PORT = 4242

# The ip of the test client is fixed in the docker-compose
TEST_CLIENT_IP = "172.20.0.20"


def send_udp_packet(src: str, dst: str):
    """Use scapy to send crafted udp packet (with spoofed ip source)."""
    payload = "test"
    packet = IP(src=src, dst=dst) / UDP(dport=HONEYPOT_PORT) / payload
    send(packet)


def send_tcp_packet(dst: str):
    """Uses built-in socket to properly create a tcp connection."""
    payload = "test"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((dst, HONEYPOT_PORT))
    s.send(payload.encode("utf-8"))
    s.close()


def exporter_line(auth: str, dst: str, proto: str, count: str):
    """Format the exporter metric line with wanted arguments."""
    return f'honeypot_{auth}_connections_total{{dst="{dst}",port="4242",proto="{proto}"}} {count}'


def test_honeypot_exporter_listeners():
    """Test the honeypot is listening on tcp and udp.

    It will send tcp and udp packet and check if metrics are exported
    """
    send_tcp_packet(dst=HONEYPOT_IP)
    r = requests.get(HONEYPOT_EXPORTER_URL)
    assert exporter_line("authorized", HONEYPOT_IP, "tcp", 1) in r.text

    send_udp_packet(src=TEST_CLIENT_IP, dst=HONEYPOT_IP)
    r = requests.get(HONEYPOT_EXPORTER_URL)
    # As we are sending crafted udp packet, the honeypot exported somehow will
    # not display the dst ip on the exported metric, but this string "[::]"
    assert exporter_line("authorized", "[::]", "udp", 1) in r.text


def test_honeypot_exporter_authorization():
    """Test the authorization logic of the exporter.

    Only UDP packet are sent as only UDP Protocol can be spoofed.

    This test is dependant of the preceding one as the exported metrics counter
    are not reset.
    """

    # test global authorization
    send_udp_packet(src="172.21.0.10", dst=HONEYPOT_IP)
    send_udp_packet(src="172.21.0.11", dst=HONEYPOT_IP)
    r = requests.get(HONEYPOT_EXPORTER_URL)
    assert exporter_line("authorized", "[::]", "udp", 3) in r.text

    # test particular authorization
    send_udp_packet(src="172.20.0.30", dst=HONEYPOT_IP)
    send_udp_packet(src="172.23.0.30", dst=HONEYPOT_IP)
    r = requests.get(HONEYPOT_EXPORTER_URL)
    assert exporter_line("authorized", "[::]", "udp", 5) in r.text

    # test unauthorized
    send_udp_packet(src="172.22.0.10", dst=HONEYPOT_IP)
    send_udp_packet(src="172.22.0.20", dst=HONEYPOT_IP)
    r = requests.get(HONEYPOT_EXPORTER_URL)
    assert exporter_line("unauthorized", "[::]", "udp", 2) in r.text
