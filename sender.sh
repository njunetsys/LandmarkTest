#!/bin/sh

sudo iptables -A INPUT -p tcp -j NFQUEUE
sudo iptables -A OUTPUT -p tcp --dport 5001 -j NFQUEUE
