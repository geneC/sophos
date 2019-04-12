#!/usr/bin/perl

# del-user-remote.pl
# Copyright 2014-2019, Gene Cumm <genecumm@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston MA 02110-1301, USA; either version 2 of the License, or
# (at your option) any later version; incorporated herein by reference.

# Delete remote users from config.  Remote user objects are only needed for
# VPN access, email control and by-user network rules, not general HTTPProxy
# use.

use warnings;
use strict;

use Astaro::ConfdPlRPC;

my $confd = Astaro::ConfdPlRPC->new or die 'cannot connect';

$confd->lock or die 'cannot lock';

for my $user (@{ $confd->get_objects(qw(aaa user)) }) {
  # Deleting a user also delete's a user's hostkeys, metakeys, and usernetwork
  next if $user->{data}{authentication} ne 'remote';
  # Edit for list/expressions of excluded users
  next if $user->{data}{name} =~ /^(excludUser1|excludUser2)$/;
  print "removing $user->{data}{name} ... ";
  # not sure which of the following 2 calls is slow when there's 2000
  #   superfluous users
  $confd->refresh_lock;
  my $ret = $confd->del_object($user->{ref});
  if ($ret) {
    print "ok\n";
  } else {
    print "failed, aborting\n";
    $confd->disconnect;
    exit 1;
  }
}
print "Deleted $i users\n";

$confd->commit or die 'cannot commit';
$confd->disconnect;

exit 0;
