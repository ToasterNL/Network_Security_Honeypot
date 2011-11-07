#!/bin/sh
iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 22 -j DNAT --to 192.168.1.39:9988
