#!/bin/sh

sudo iptables -A INPUT -p tcp --sport 5001 -j NFQUEUE
sudo iptables -A INPUT -p tcp --dport 5001 -j NFQUEUE
sudo iptables -A OUTPUT -p tcp --sport 5001 -j NFQUEUE
sudo iptables -A OUTPUT -p tcp --dport 5001 -j NFQUEUE
