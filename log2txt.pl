#!/usr/bin/perl

# Parse Sophos UTM v9/Astaro ASG v8 log lines to text formats

# This list is based on the fields in http.log from UTM-9.2 for pass/block plus error

sub syslog2msg {
	my ($ins) = @_;
	my $pri, $rems, $ts, $host, $proc, $msg;

	if ($ins =~ /^<\d{1,3}>\s.*/) {
		($pri, $rems) = ($ins =~ /^<(\d+)>\s+(.*)/);
	} else {
		$rems = $ins;
		$pri='';
	}
	($ts, $host, $proc, $msg) = split(/ /, $rems, 4);
	return ($pri, $ts, $host, $proc, $msg);
}

sub syslogmsg2hash {
	my ($ins) = @_;
	my %d, $msg, @s, $e, $f, $v;

	@s = split(/([-a-z]+="(?:.*?[^\\]|)" ?)/, $ins);
	$msg = $s[scalar(@s)-1];	# will contain \n
	foreach $e (@s[0..(scalar(@s) - 2)]) {
		if (!($e eq '')) {
print '-', $e, "-\n";
			($f, $v) = split(/=/, $e, 2);
			$d{$f} = $v;
		}
	}
	chomp($msg);
	return ($msg, %d);
}

sub syslog2hash {
	my ($ins) = @_;
	my $pri, $rems, $ts, $host, $proc, $body, $msg, %d;
	my $f, $nf, $i = 1;	# field, new field, index

	($pri, $ts, $host, $proc, $body) = syslog2msg($ins);
	($msg, %d) = syslogmsg2hash($body);
	foreach $f ('pri', 'ts', 'host', 'proc', 'msg') {
		if (exists $d{$f}) {
			$nf = $f . $i++;
			while (exists $d{$nf}) {
				$nf = $f . $i++;
				last if ($i > 100);
			}
			$d{$nf} = $d{$f};
			delete $d{$f};
		}
		$d{$f} = ${$f};
	}
	return %d;
}

sub sysloghash2csv {
	my ($d, $k) = @_;
	my $r = '';

	delete $d{'pri'};
	$r = $d{'ts'} . ',' . $d{'host'} . ','. $d{'proc'};
	delete @d{'ts', 'host', 'proc'};
	foreach $f (@$k[3..(scalar(@$k) - 1)]) {
# print $f, "\n";
		if (exists$d{$f}) {
			$r .= ',' . $d{$f};
			delete $d{$f};
		} else {
			$r .= ',';
		}
	}
# print join(';', keys %d), "\n";
# print join('_', @$k), "\n";
	$r .=  "\n";	# msg had \n chomp()'d
	return $r;
}

sub log2txt_test {
	# test syslog2msg
# 	while (<STDIN>) {
# 		print join(',', syslog2msg($_));
# 	}

	# test syslog2hash
	my %d;
	my @k = ('ts', 'host', 'proc', 'id', 'severity', 'sys', 'sub', 'name', 'action', 'method', 'srcip', 'dstip', 'user', 'statuscode', 'cached', 'profile', 'filteraction', 'size', 'request', 'url', 'exceptions', 'error', 'authtime', 'dnstime', 'cattime', 'avscantime', 'fullreqtime', 'device', 'auth', 'reason', 'category', 'reputation', 'categoryname', 'content-type', 'function', 'file', 'line', 'message', 'msg');
	while (<STDIN>) {
		%d = syslog2hash($_);
		# print ($d{'ts'}, ',', $d{'host'}, ',', $d{'proc'} , "\n");
		# now test sysloghash2csv
		print sysloghash2csv(\%d, \@k);
	}
	print join(',', @k), "\n";
}

sub log2txt_main {
	log2txt_test();
}

log2txt_main();
