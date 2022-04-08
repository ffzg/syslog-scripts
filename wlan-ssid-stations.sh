grep hostapd: /var/log/daemon.log | grep wlan | grep 'authenticated$' | awk '{ print $6 " " $8 }' | sort -u | cut -d: -f1 | uniq -c | \
	awk '
	$2 == "wlan0" { print "eduroam 2.4G " $1 }
	$2 == "wlan0-1" { print "FFZGwlan 2.4G " $1 }
	$2 == "wlan0-2" { print "FF-LOCAL 2.4G " $1 }
	$2 == "wlan1" { print "eduroam 5G " $1 }
	$2 == "wlan1-1" { print "FFZGwlan 5G " $1 }
	$2 == "wlan1-2" { print "FF-LOCAL 5G " $1 }
	'
