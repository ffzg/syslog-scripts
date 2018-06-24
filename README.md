# syslog-scripts
filter syslog files, create counts...

## group output by time

zgrep squirrelmail /var/log/mail.log* | cut -d: -f -5 | ./group-by-10m.sh


