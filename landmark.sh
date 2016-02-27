#!/bin/sh

sudo iptables -A INPUT -p tcp -j NFQUEUE
