sudo tail -f /var/log/user.log | grep ntopng: | sed -e 's/<[^>]*>//g'
