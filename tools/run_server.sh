#!/bin/sh
# Mirror outgoing QUIC (UDP/443) packets to the quic-network-simulator so they
# appear in the pcap capture (trace_node_right.pcap). Original packets continue
# via Docker's bridge routing so the client still receives them.
# The sim listens on the rightnet at 193.167.100.2 (both IPv4 and IPv6).
iptables  -t mangle -A OUTPUT -p udp --sport 443 -j TEE --gateway 193.167.100.2  2>/dev/null || true
ip6tables -t mangle -A OUTPUT -p udp --sport 443 -j TEE --gateway fd00:cafe:cafe:100::2 2>/dev/null || true
exec /server
