#!/bin/sh
TIME=`date +%s`
BACKUP_DIR="backups"
LOG_DIR="/home/util139/logs/"
mkdir ${BACKUP_DIR}
#cp -R ${LOG_DIR} ${BACKUP_DIR}
rsync -ar --max-delete=0 ${LOG_DIR} ${BACKUP_DIR}

