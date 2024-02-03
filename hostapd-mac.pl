#!/usr/bin/perl
use warnings;
use strict;
use autodie;
use Data::Dump qw(dump);

my $debug = $ENV{DEBUG};

my $stat;

my $cmd = "grep -E '(hostapd:|dhcpd)' /var/log/syslog";
   $cmd = "tail -$ENV{LAST} /var/log/syslog | grep -E '(hostapd:|dhcpd)'" if $ENV{LAST};

if ( @ARGV ) {
   $cmd = "zgrep -E '(hostapd:|dhcpd)' @ARGV";
}

my $pipe;
if ( ! -t ) {
	warn "# command piped into detected";
	open($pipe, '<', '/dev/stdin');
} else {
	warn "#cmd $cmd\n";
	open($pipe, '-|', $cmd);
}

my %mon2num = qw(
  jan 1  feb 2  mar 3  apr 4  may 5  jun 6
  jul 7  aug 8  sep 9  oct 10 nov 11 dec 12
);


sub mdt2iso {
	my ( $mon, $d, $t ) = @_;
	my $m = $mon2num{lc$mon};

	$t = sprintf "%04d-%02d-%02dT%s",
		$m <= 2 ? 2024 : 2023, $m, $d, $t;
	warn "## $mon $d $t -> $t\n" if $debug;
	return $t;
}

while(my $line = <$pipe>) {
	chomp $line;

	# grep pipe in
	# /var/log/syslog-20240201.gz:Jan 31 09:27:07 dns01 dhcpd[2453293
	$line =~ s{^/var/log/[^:]+:}{};

	# rewrite time to iso
	# Feb  3 10:40:18 wap-lib-1s hostapd: wlan0: AP-STA-DISCONNECTED 0a:51:07:36:ec:3d
	$line =~ s{^(\w\w\w)\s+(\d+)\s([0-2][0-9:]*)}{mdt2iso($1,$2,$3)}ge;

	warn "$line\n" if $debug;

	if (
	# 2024-02-03T11:20:39+01:00 wap-b300-j hostapd: wlan0-2: AP-STA-DISCONNECTED ec:63:d7:f9:44:c1
	# 2024-02-03T13:36:33.306803+01:00 wap-lib-0j hostapd: wlan1: AP-STA-CONNECTED 64:79:f0:5b:8e:f7
		my ($t, $wap, $if, $status, $mac ) = $line =~
	       	m/^(\S+) (\S+) \S+ ([^:]+): AP-STA-(\S+) (\S+)/ ) {

		warn "$t $wap $if $status $mac\n";
		$stat->{$mac}->{ $t .' '. $wap }->{$status} = $if;

	} elsif (
	# 2024-02-03T13:49:02.915895+01:00 dns01 dhcpd[2453293]: DHCPREQUEST for 10.5.10.129 from c2:ee:50:b1:76:9b via eth11
	# 2024-02-03T13:51:32.058965+01:00 dns01 dhcpd[2453293]: DHCPACK on 10.5.6.177 to 16:37:fb:a1:96:54 via eth11
	# 2024-02-03T13:45:31.714417+01:00 pauk dhcpd: DHCPACK on 193.198.214.228 to 00:15:5d:d5:83:07 (atlas) via eth0
		my ($t,   $server,     $status,     $ip, $mac, $if ) = $line =~
	       	m/^(\S+) (\S+) dhcpd\S+ (\S+) on (\S+) to (\S+) .*via (\S+)/ ) {

		if ( exists $stat->{$mac} ) {
			warn "$t $server $if $status $mac $ip\n";
			$stat->{$mac}->{ $t .' '. $server }->{$status} = $ip;
		}

	} else {
		warn "IGNORE $line\n" if $debug && $line =~ m/hostap/
	}
}

print dump($stat),$/;
