#!/bin/sh

sudo iptables -A INPUT -p udp -j NFQUEUE
