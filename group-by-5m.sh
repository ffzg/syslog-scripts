#!/bin/sh -e

sed -e 's/[0-4]:[0-9][0-9]\(,[0-9]*\)* /0:xx /' -e 's/[5-9]:[0-9][0-9]\(,[0-9]*\)* /5:xx /' -e 's/\[[0-9]*\]//' -e 's,/var/log/,,' -e 's/[0-9][0-9].gz:[A-Z][a-z][a-z] //' | sort | uniq -c
