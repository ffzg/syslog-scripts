#!/bin/sh -xe

tail -f /var/log/syslog | egrep ' (wap|core|sw-|dox1x)'
