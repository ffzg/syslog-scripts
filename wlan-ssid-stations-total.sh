grep hostapd: /var/log/daemon.log | grep wlan | grep 'authenticated$' | \
	awk '
	$6 == "wlan0:"   { print "eduroam "  $8 }
	$6 == "wlan0-1:" { print "FFZGwlan " $8 }
	$6 == "wlan0-2:" { print "FF-LOCAL " $8 }
	$6 == "wlan1:"   { print "eduroam "  $8 }
	$6 == "wlan1-1:" { print "FFZGwlan " $8 }
	$6 == "wlan1-2:" { print "FF-LOCAL " $8 }
	' | \
       	sort -u | cut -d" " -f1 | uniq -c
