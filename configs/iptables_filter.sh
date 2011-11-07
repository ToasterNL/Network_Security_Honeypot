#!/bin/sh
iptables -A OUTPUT -p tcp --dport 25 -j REJECT # smtp
iptables -A OUTPUT -p tcp --dport 137 -j REJECT # netbios
iptables -A OUTPUT -p udp --dport 137 -j REJECT # netbios
iptables -A OUTPUT -p tcp --dport 138 -j REJECT # netbios
iptables -A OUTPUT -p udp --dport 138 -j REJECT # netbios
iptables -A OUTPUT -p tcp --dport 139 -j REJECT # netbios
iptables -A OUTPUT -p udp --dport 139 -j REJECT # netbios
iptables -A OUTPUT -p udp --dport 5060 -j REJECT # sip
iptables -A OUTPUT -p udp --dport 5061 -j REJECT # sip
