# syslog-scripts
filter syslog files, create counts...

# group output by time

## overview of any log file

This should give you idea what you can grep for to find in that file:

    cat /var/log/syslog | cut -d' ' -f-5 | sed 's/\[[0-9]*\]//' | ./group-by-10m.sh | less -S

## mail

    grep -i from= /var/log/mail.log | grep to= | sed -e 's/\[.*from=/ from=/' | ./group-by-1h.sh  | less -S

## squirrelmail

    grep squirrelmail /var/log/mail.log | cut -d: -f -5 | ./group-by-10m.sh | less -S

## wordpress

    grep 'wordpress\[' /var/log/auth.log | ./group-by-10m.sh  | less -S


# add dateext to all daily logrotate.d

    perl -p -i -n -e 's/(\s+)daily/$1daily\n$1dateext/' /etc/logrotate.d/*

# slapd

show uses with more than 5 ldap ENTRY requests

    grep slapd /var/log/syslog | grep ENTRY | sed -e 's/: conn=.*ENTRY//' | ./group-by-10m.sh | grep -v '^ *[1234] ' | less -S

# fail2ban

show number of ban/unban events on group by priod

    grep NOTICE /var/log/fail2ban.log | sed -e 's/ [0-9\.]*$//' | ./group-by-1h.sh
