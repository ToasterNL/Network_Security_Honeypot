#!/bin/sh
/usr/sbin/rsyslogd -c5 -i `pwd`/rsyslog.pid -f `pwd`/rsyslog.conf -d
