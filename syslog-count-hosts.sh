#!/bin/sh -xe
cat `test ! -z "$1" && echo $1 || echo /var/log/messages` | cut -d' ' -f4 | sort | uniq -c
