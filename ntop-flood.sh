sudo zgrep ntopng: /var/log/user.log* | sed -e 's/<[^>]*>//g' | grep -v blacklisted | grep -i flood 
