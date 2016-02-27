#!/bin/sh

sudo iptables -A INPUT -p udp -j NFQUEUE
sudo iptables -A OUTPUT -p udp --sport 5001 -j NFQUEUE
