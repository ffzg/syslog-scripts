#!/bin/sh -xe

sed -e 's/[0-9]:[0-9][0-9] /x:xx /' -e 's/\[[0-9]*\]//' | sort | uniq -c
