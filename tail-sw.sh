#!/bin/sh -xe

op='-f'
test ! -z "$1" && op=$1

tail $op /var/log/syslog \
| egrep --line-buffered ' (wap|core|sw-|dox1x)' \
| egrep --line-buffered -v '(core system user syslog logged|hostapd:)'
