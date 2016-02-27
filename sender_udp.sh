#!/bin/sh

sudo iptables -A INPUT -p udp -j NFQUEUE
sudo iptables -A OUTPUT -p udp --dport 5001 -j NFQUEUE
