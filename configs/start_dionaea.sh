#!/bin/sh
sudo dionaea -u nobody -g nogroup -w /opt/dionaea -p /opt/dionaea/var/run/dionaea.pid -c /etc/dionaea/dionaea.conf -D

