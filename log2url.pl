#!/usr/bin/perl

# log2url.pl
# Copyright 2018, Gene Cumm <genecumm@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston MA 02110-1301, USA; either version 2 of the License, or
# (at your option) any later version; incorporated herein by reference.

# Parse Sophos UTM v9/Astaro ASG v8 log lines to just URLs

# This list is based on the fields in http.log from UTM-9.5 for pass/block plus error

# use strict;

sub syslog2url1 {
	my ($ins) = @_;
	my ($r);

	if ($ins =~ m/" url=".+?" /) {
		($r) = ($ins =~ m/" url="(.+?)" /)
	}

	return $r;
}

sub log2url_test {
	my ($s);
	while (<STDIN>) {
		$s = syslog2url1($_);
		print $s . "\n";
	}
}

sub log2url1 {
	my ($s);
	while (<STDIN>) {
		($s) = (m/" url="(.+?)" / );
		print $s . "\n";
	}
}

# Doesn't clear $1 as desired
sub log2url2 {
	my ($s);
	while (<STDIN>) {
		m/" url="(.+?)" / ;
		print $1 . "\n";
	}
}

sub log2url_main {
# 	log2url_test();
	log2url1();
}

log2url_main();
