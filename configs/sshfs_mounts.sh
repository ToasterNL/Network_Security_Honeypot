#!/bin/sh
#sudo -u snort sshfs util139@192.168.1.210:/home/util139/logs/snort/ /var/log/remote_snort/
sudo sshfs util139@192.168.1.210:/home/util139/logs/suricata/ /var/log/remote_suricata/
sudo sshfs util139@192.168.1.210:/home/util139/logs/apache2 /var/log/remote_apache2
sudo sshfs util139@192.168.1.210:/home/util139/logs/nginx/ `pwd`/www/build/remote_logs
