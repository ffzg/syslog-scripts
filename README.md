# syslog-scripts
filter syslog files, create counts...

# group output by time

## mail

    grep -i from= /var/log/mail.log | grep to= | sed -e 's/\[.*from=/ from=/' | ./group-by-1h.sh  | less -S

## squirrelmail

    grep squirrelmail /var/log/mail.log | cut -d: -f -5 | ./group-by-10m.sh | less -S

## wordpress

    grep 'wordpress\[' /var/log/auth.log | ./group-by-10m.sh  | less -S



