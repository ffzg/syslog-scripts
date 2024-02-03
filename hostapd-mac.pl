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
	       	m/^(\w+\s+\d+\s+\S+) (\S+) \S+ ([^:]+): AP-STA-(\S+) (\S+)/ ) {

		warn "$t $wap $if $status $mac\n";
		$stat->{$mac}->{ $t .' '. $wap }->{$status} = $if;
	} elsif (
	# 2024-02-03T11:20:39+01:00 wap-b300-j hostapd: wlan0-2: AP-STA-DISCONNECTED ec:63:d7:f9:44:c1
	# 2024-02-03T13:36:33.306803+01:00 wap-lib-0j hostapd: wlan1: AP-STA-CONNECTED 64:79:f0:5b:8e:f7
		my ($t, $wap, $if, $status, $mac ) = $line =~
	       	m/^(\S+) (\S+) \S+ ([^:]+): AP-STA-(\S+) (\S+)/ ) {

		warn "$t $wap $if $status $mac\n";
		$stat->{$mac}->{ $t .' '. $wap }->{$status} = $if;

	} else {
		warn "IGNORE $line\n";
	}
}

print dump($stat),$/;
