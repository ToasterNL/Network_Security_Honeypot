#!/bin/sh
LD_LIBRARY_PATH=`pwd`/syslog-ng/usr/lib/:`pwd`/syslog-ng/lib/:$LD_LIBRARY_PATH ./syslog-ng/usr/sbin/syslog-ng -f syslog-ng.conf --module-path=`pwd`/syslog-ng/usr/lib/syslog-ng/ -R `pwd`/syslog-ng.persist -p `pwd`/syslog-ng.pid

