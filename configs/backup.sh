#!/bin/sh
TIME=`date +%s`
BACKUP_DIR="backups/backup_${TIME}"
LOG_DIR="/home/util139/logs/"
mkdir ${BACKUP_DIR}
cp -R ${LOG_DIR} ${BACKUP_DIR}

