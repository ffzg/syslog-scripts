#!/bin/sh -xe

cut -d\[ -f1 | sed 's/[0-9]:[0-9][0-9] /x:xx /' | sort | uniq -c
