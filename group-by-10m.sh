#!/bin/sh -e

sed -e 's/[0-9]:[0-9][0-9] /x:xx /' -e 's/\[[0-9]*\]//' | sort | uniq -c
