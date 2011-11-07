#!/bin/sh
ssh -nNTx -p 9022 -R 9876:localhost:9876 kerckhoffs@192.168.1.39 >/dev/null 2>&1 &
