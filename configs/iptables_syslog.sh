#!/bin/sh
sudo iptables -I INPUT -m state --state NEW -j LOG --log-prefix "New Connection: "
sudo iptables -I OUTPUT -m state --state NEW -j LOG --log-prefix "New Connection: "
