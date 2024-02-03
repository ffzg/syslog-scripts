#!/usr/bin/perl
use warnings;
use strict;
use autodie;
use Data::Dump qw(dump);

my $stat;

open(my $pipe, '-|', 'grep hostapd: /var/log/syslog');
while(my $line = <$pipe>) {
	chomp $line;
	# Feb  3 10:40:18 wap-lib-1s hostapd: wlan0: AP-STA-DISCONNECTED 0a:51:07:36:ec:3d
	if (
		my ( $t, $wap, $if, $status, $mac ) = $line =~
	       	m/(\w+\s+\d+\s+\S+) (\S+) \S+ ([^:]+): AP-STA-(\S+) (\S+)/ ) {

		warn "$t $wap $if $status $mac\n";
		$stat->{$mac}->{ $t .' '. $wap }->{$status} = $if;
	} else {
		warn "IGNORE $line\n";
	}
}

print dump($stat),$/;
