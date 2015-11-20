#!/usr/bin/perl

# log2txt.pl
# Copyright 2014, Gene Cumm <genecumm@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston MA 02110-1301, USA; either version 2 of the License, or
# (at your option) any later version; incorporated herein by reference.

# Parse Sophos UTM v9/Astaro ASG v8 log lines to text formats

# This list is based on the fields in http.log from UTM-9.2 for pass/block plus error

# use strict;

sub syslog2msg {
	my ($ins) = @_;
	my ($pri, $rems, $ts, $host, $proc, $msg);

	if ($ins =~ /^<\d{1,3}>\s.*/) {
		($pri, $rems) = ($ins =~ /^<(\d+)>\s+(.*)/);
	} else {
		$rems = $ins;
		$pri='';
	}
	($ts, $host, $proc, $msg) = split(/ /, $rems, 4);
	chomp($ts, $host, $proc);
	return ($pri, $ts, $host, $proc, $msg);
}

sub syslogmsg2hash_matop1 {
	my ($ins) = @_;
	my (%d, $f, $v);

	($f, $ins) = ($ins =~ m/^([-a-z]+)=(.*)$/o );
	if ($f =~ /./ ) {
		($v, $ins) = ($ins =~ m/^(".*?")(?: |$)(.*)$/o );
	}
# print "got '$f' = '$v'\n";
	while ($v =~ /./ ) {
# print "adding '$f' = '$v'\n";
		$d{$f} = $v;
		($f, $ins) = ($ins =~ m/^([-a-z]+)=(.*)$/o );
		if ($f =~ /./ ) {
			($v, $ins) = ($ins =~ m/^(".*?")(?: |$)(.*)$/o );
		} else {
			$v = '';
		}
# print "got '$f' = '$v'\n";
	}
	chomp($ins);
	return ($ins, %d);
}

sub syslogmsg2hash_matop2 {
	my ($ins) = @_;
	my (%d, $f, $v);

	($f, $v, $ins) = ($ins =~ m/^(?:([-a-z]+)=(".*?")(?: |$))?(.*)$/o );
# print "got '$f' = '$v'\n";
	while ($v =~ /./ ) {
# print "adding '$f' = '$v'\n";
		$d{$f} = $v;
		($f, $v, $ins) = ($ins =~ m/^(?:([-a-z]+)=(".*?")(?: |$))?(.*)$/o );
# print "got '$f' = '$v'\n";
	}
	chomp($ins);
	return ($ins, %d);
}

sub syslogmsg2hash {
	my ($ins) = @_;
	my (%d, $msg, @s, $e, $f, $v, $l);

# 	@s = split(/([-a-z]+="(?:|.*?[^\\])")(?: |$)/, $ins);
# 	@s = split(/([-a-z]+="(?:|.*?)")(?: |$)/, $ins);
# 	@s = split(/([-a-z]+="(?:.*?)")(?: |$)/o, $ins);
#xx	@s = split(/(.+?=".*?")(?: |$)/o, $ins);	# Syntactically incorrect
# 	@s = split(/([^" ]+?=".*?")(?: |$)/o, $ins);
# 	@s = split(/([-a-z]+=".*?") ?/o, $ins);
	@s = split(/([-a-z]+=".*?")(?: |$)/o, $ins);
	$l = @s - 2;
	$msg = $s[$l+1];	# will contain \n
	foreach $e (@s[0..$l]) {
		if (!(($e eq '') or ($e eq ' '))) {
		# if (!(($e =~ /^ ?$/))) {
# print '-', $e, "-\n";
			($f, $v) = split(/=/, $e, 2);
# print "adding '$f' = '$v' \n";
			$d{$f} = $v;
		}
	}
	chomp($msg);
	return ($msg, %d);
}

sub syslogmsgh2hash {
	my ($ins, $d) = @_;
	my ($msg, @s, $e, $f, $v, $l);

# print "    --in '" . join("','", values $d) . "'\n";
# print "    --host='" . ${$d}{host} . "'\n";

# 	@s = split(/([-a-z]+="(?:|.*?[^\\])")(?: |$)/, $ins);
# 	@s = split(/([-a-z]+="(?:|.*?)")(?: |$)/, $ins);
# 	@s = split(/([-a-z]+="(?:.*?)")(?: |$)/o, $ins);
#xx	@s = split(/(.+?=".*?")(?: |$)/o, $ins);	# Syntactically incorrect
# 	@s = split(/([^" ]+?=".*?")(?: |$)/o, $ins);
# 	@s = split(/([-a-z]+=".*?") ?/o, $ins);
	@s = split(/([-a-z]+=".*?")(?: |$)/o, $ins);
	$l = @s - 2;
	$msg = $s[$l+1];	# will contain \n
	foreach $e (@s[0..$l]) {
		if (!(($e eq '') or ($e eq ' '))) {
		# if (!(($e =~ /^ ?$/))) {
# print '-', $e, "-\n";
			($f, $v) = split(/=/, $e, 2);
# print "adding '$f' = '$v' \n";
# 			if (exists $$d{$f}) {
# 				$i = 1;
# 				$nf = $f . $i++;
# 				while (exists $$d{$nf}) {
# 					$nf = $f . $i++;
# 					last if ($i > 100);
# 				}
# 				$f = $nf;
# 			}
			${$d}{$f} = $v;
		}
	}
# print "    --out '" . join("','", values $d) . "'\n";
	chomp($msg);
	return ($msg, %$d);
}

sub syslogmsg2hash_select {
	return syslogmsg2hash_split(@_);
# 	return syslogmsg2hash_matop1 @_;
# 	return syslogmsg2hash_matop2 @_;
}

sub syslog2hash {
	my ($ins) = @_;
	my ($pri, $rems, $ts, $host, $proc, $body, $msg, %d);
	my ($f, $nf, $i);	# field, new field, index

	($pri, $ts, $host, $proc, $body) = syslog2msg($ins);
#$msg = $body;
# print "    --got '$pri' '$ts' '$host' '$proc'\n";
# 	($msg, %d) = syslogmsg2hash($body);
	%d = (pri=>$pri, ts=>$ts, host=>$host, proc=>$proc);
	($msg, %d) = syslogmsgh2hash($body, \%d);
# print "    --hash '" . join("','", values %d) . "'\n";
# 	no strict "refs";
# 	foreach $f ('pri', 'ts', 'host', 'proc', 'msg') {
# 		if (exists $d{$f}) {
# 			$i = 1;
# 			$nf = $f . $i++;
# 			while (exists $d{$nf}) {
# 				$nf = $f . $i++;
# 				last if ($i > 100);
# 			}
# 			$d{$nf} = $d{$f};
# 			delete $d{$f};
# 		}
# 		$d{$f} = ${$f};
# print "  --add '$f' = '" . $$f . "'\n";
# 	}
	$f = 'msg';
	if (exists $d{$f}) {
		$i = 1;
		$nf = $f . $i++;
		while (exists $d{$nf}) {
			$nf = $f . $i++;
			last if ($i > 100);
		}
		$d{$nf} = $d{$f};
		delete $d{$f};
	}
	$d{$f} = "\"$msg\"";
# print "val-" . join(',', values %$d) . "\"\n";
	return %d;
}

sub sysloghash2csv {
	my ($d, $k) = @_;
	my ($r, $f);
	my ($dkc);

# print "val-" . join(',', values %$d) . "\"\n";
	delete $$d{'pri'};
	$r = '"' . $$d{'ts'} . '","' . $$d{'host'} . '","'. $$d{'proc'} . '"';
	delete @$d{'ts', 'host', 'proc'};
	foreach $f (@$k[3..(scalar(@$k) - 1)]) {
# print ($f . '"="' . $$d{$f} . "\"\n");
		if (exists $$d{$f}) {
			$r .= ',' . $$d{$f};
			delete $$d{$f};
		} else {
			$r .= ',""';
		}
	}
# print join(';', keys %d), "\n";
$dkc = %d;
if ( ${%d} > 0) { print join(';', keys %d), "\n"; }
# print join('_', @$k), "\n";
	foreach $f (keys %$d) {
print "New key '$f' \n";
		push @$k, $f;
		$r .= ',' . $$d{$f};
		delete $$d{$f};
	}
	$r .=  "\n";	# msg had \n chomp()'d
	return $r;
}

sub syslogbody_fixup {
	${$_[0]} =~ s/" reputation="(.*?)(" category=".*?" reputation=")(.*?" ?)/\2\1;\3/o;
	${$_[0]} =~ s/( category=".*?" .*?)( reason=".*?")$/\2\1/o;
	${$_[0]} =~ s/^(.*?)(id=".*?" .*?)$/\2 \1/o;
	${$_[0]} =~ s/( name=".*?"(?: action=".*?")?)( user=".*?".*?)( method=".*?")/\1\3\2/o;
	${$_[0]} =~ s/( user=".*?")( srcip=".*?"(?: dstip=".*?")?)/\2\1/o;
}

sub syslogbody2arr {
# 	return (${$_[0]} =~ m/(?:id="(.*?)" )(?:severity="(.*?)" )(?:sys="(.*?)" )(?:sub="(.*?)" )(?:name="(.*?)" )?(?:action="(.*?)" )?(?:method="(.*?)" )?(?:fwrule="(.*?)" )?(?:initf="(.*?)" )?(?:outitf="(.*?)" )?(?:srcmac="(.*?)" )?(?:dstmac="(.*?)" )?(?:srcip="(.*?)" )?(?:dstip="(.*?)" )?(?:user="(.*?)" )?(?:statuscode="(.*?)" )?(?:cached="(.*?)" )?(?:profile="(.*?)" )?(?:filteraction="(.*?)" )?(?:size="(.*?)" )?(?:request="(.*?)" )?(?:url="(.*?)" )?(?:exceptions="(.*?)" )?(?:error="(.*?)" ?)?(?:authtime="(.*?)" )?(?:dnstime="(.*?)" )?(?:cattime="(.*?)" )?(?:avscantime="(.*?)" )?(?:fullreqtime="(.*?)" )?(?:device="(.*?)" )?(?:auth="(.*?)" )?(?:reason="(.*?)" ?)?(?:category="(.*?)" )?(?:reputation="(.*?)" )?(?:categoryname="(.*?)" ?)?(?:extension="(.*?)" )?(?:filename="(.*?)" ?)?(?:content-type="(.*?)" ?)?(?:application="(.*?)" ?)?(?:function="(.*?)" )?(?:file="(.*?)" )?(?:line="(.*?)" )?(?:caller="(.*?)" )?(?:engine="(.*?)" ?)?(?:sid="(.*?)" ?)?(?:facility="(.*?)" ?)?(?:client="(.*?)" ?)?(?:call="(.*?)" ?)?(?:lock="(.*?)" ?)?(?:storage="(.*?)" ?)?(?:message="(.*?)" ?)?(.*?)$/o);	#(.*?)$
	return (${$_[0]} =~ m/(?:id="(.*?)" )(?:severity="(.*?)" )(?:sys="(.*?)" )(?:sub="(.*?)" )(?:name="(.*?)" )?(?:action="(.*?)" )?(?:method="(.*?)" )?(?:fwrule="(.*?)" )?(?:initf="(.*?)" )?(?:outitf="(.*?)" )?(?:srcmac="(.*?)" )?(?:dstmac="(.*?)" )?(?:srcip="(.*?)" )?(?:dstip="(.*?)" )?(?:user="(.*?)" )?(?:statuscode="(.*?)" )?(?:cached="(.*?)" )?(?:profile="(.*?)" )?(?:filteraction="(.*?)" )?(?:size="(.*?)" )?(?:request="(.*?)" )?(?:url="(.*?)" )?(?:exceptions="(.*?)" )?(?:error="(.*?)" ?)?(?:authtime="(.*?)" )?(?:dnstime="(.*?)" )?(?:cattime="(.*?)" )?(?:avscantime="(.*?)" )?(?:fullreqtime="(.*?)" )?(?:device="(.*?)" )?(?:auth="(.*?)" )?(?:reason="(.*?)" ?)?(?:category="(.*?)" )?(?:reputation="(.*?)" )?(?:categoryname="(.*?)" ?)?(?:extension="(.*?)" )?(?:filename="(.*?)" ?)?(?:content-type="(.*?)" ?)?(?:application="(.*?)" ?)?(?:sid="(.*?)" ?)?(?:facility="(.*?)" ?)?(?:client="(.*?)" ?)?(?:pid="(.*?)" )?(?:call="(.*?)" ?)?(?:result="(.*?)" ?)?(?:lock="(.*?)" ?)?(?:storage="(.*?)" ?)?(?:function="(.*?)" )?(?:file="(.*?)" )?(?:line="(.*?)" )?(?:caller="(.*?)" )?(?:engine="(.*?)" ?)?(?:proto="(.*?)" )?(?:length="(.*?)" )?(?:tos="(.*?)" )?(?:prec="(.*?)" )?(?:ttl="(.*?)" )?(?:srcport="(.*?)" )?(?:dstport="(.*?)" )?(?:tcpflags="(.*?)" )?(?:type="(.*?)" )?(?:code="(.*?)" )?(?:message="(.*?)" ?)?(.*?) *$/o);	#(.*?)$
}

sub syslog2csv {
	my ($ins) = @_;
	my ($pri, $rems, $ts, $host, $proc, $body, $msg, @d);
	my ($r);

	($pri, $ts, $host, $proc, $body) = syslog2msg($ins);
# 	$body =~ s/" reputation="(.*?)(" category=".*?" reputation=")(.*?" ?)/\2\1;\3/o;
# 	$body =~ s/( category=".*?" .*?)( reason=".*?")$/\2\1/o;
	syslogbody_fixup(\$body);
	$r = '"' . $ts . '","' . $host . '","'. $proc . '","' . join('","', @d) . "\"\n";
	return $r;
}

sub syslog2tsv {
	my ($ins) = @_;
	my ($pri, $rems, $ts, $host, $proc, $body, $msg, @d);
	my ($r);

	($pri, $ts, $host, $proc, $body) = syslog2msg($ins);
	syslogbody_fixup(\$body);
	@d = syslogbody2arr(\$body);
	$r = '"' . $ts . '"	"' . $host . '"	"'. $proc . '"	"' . join('"	"', @d) . "\"\n";
	return $r;
}

sub syslog2csvd {
	my ($ins, @k) = @_;
	my ($pri, $rems, $ts, $host, $proc, $body, $msg, @d, $re);
	my ($r);

# print join(',', @k) . "\n";
	($pri, $ts, $host, $proc, $body) = syslog2msg($ins);
	syslogbody_fixup(\$body);
	$re = '(?:' . join('="(.*?)"(?: |$))?(?:', @k[3..(scalar(@k) - 2)]). '="(.*?)"(?: |$))?';
# print $re . "\n";
	@d = ($body =~ m/^$re(.*?)$/o);	#(.*?)$
	$r = '"' . $ts . '","' . $host . '","'. $proc . '","' . join('","', @d) . "\"\n";
	return $r;
}

sub log2txt_test {
	# test syslog2msg
# 	while (<STDIN>) {
# 		print join(',', syslog2msg($_));
# 	}

	# test syslog2hash
	my (%d, @k, $s, $kc);
	@k = ('ts', 'host', 'proc', 'id', 'severity', 'sys', 'sub', 'name', 'action', 'method', 'srcip', 'dstip', 'user', 'statuscode', 'cached', 'profile', 'filteraction', 'size', 'request', 'url', 'exceptions', 'error', 'authtime', 'dnstime', 'cattime', 'avscantime', 'fullreqtime', 'device', 'auth', 'extension', 'filename', 'reason', 'category', 'reputation', 'categoryname', 'content-type', 'application', 'function', 'file', 'line', 'message', 'msg');
	print join(',', @k), "\n";
	$kc = @k;
	while (<STDIN>) {
# 		%d = syslog2hash($_);
# 		# print ($d{'ts'}, ',', $d{'host'}, ',', $d{'proc'} , "\n");
# 		# now test sysloghash2csv
# 		$s = sysloghash2csv(\%d, \@k);
# 		# %d = ();	# should already be empty and unnecessary
		$s = syslog2csv($_);
# 		$s = syslog2csvd($_, @k);
		print $s;
	}
	if ( scalar(@k) > $kc) {
		# print "FinalKeys\n";
		print join(',', @k), "\n";
	}
}

sub log2txt_main {
	log2txt_test();
}

log2txt_main();
