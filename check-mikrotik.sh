#!/bin/sh -e

# no args, less current
test -z "$1" && grep -i -E '(48:a9:8a|64:d1:54|b8:69:f4|c4:ad:34|cc:2d:e0)' /var/log/syslog | less

# with args, iterate over files
while [ -e "$1" ] ; do
	echo "# $1"
	zgrep -i -E '(48:a9:8a|64:d1:54|b8:69:f4|c4:ad:34|cc:2d:e0)' $1 | grep -v firewall
	shift
done

