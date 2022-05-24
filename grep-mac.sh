#!/bin/sh

mac=$( echo $1 | sed 's/:/[:-]/g' )
grep -i $mac /var/log/syslog
