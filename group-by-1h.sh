#!/bin/sh -e

sed -e 's/[0-9][0-9]:[0-9][0-9] /xx:xx /' -e 's/\[[0-9]*\]//' | sort | uniq -c
