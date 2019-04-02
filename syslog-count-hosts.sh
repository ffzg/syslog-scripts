#!/bin/sh -xe
#cat `test ! -z "$1" && echo $1 || echo /var/log/messages` | cut -d' ' -f4 | sort | uniq -c
cat `test ! -z "$1" && echo $1 || echo /var/log/messages` | cut -d' ' -f-5 | sed 's/:[0-9][0-9]:[0-9][0-9]/:__:__/' | sort | uniq -c
