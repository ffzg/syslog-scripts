#!/bin/sh -xe

sudo tail -f /var/log/auth.log | grep --line-buffer 'wordpress\['
