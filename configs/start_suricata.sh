#!/bin/sh
LD_LIBRARY_PATH=/home/kerckhoffs/honeypot_software/suricata/build/lib/ /home/kerckhoffs/honeypot_software/suricata/build/bin/suricata -c /home/kerckhoffs/honeypot_software/suricata/build/suricata-debian.yaml --pfring -D
