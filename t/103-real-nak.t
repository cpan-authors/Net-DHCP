#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 19;
use Test::Warn qw( warning_like );
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my %values = (
    htype   => 0,
    hlen    => 0,
    hops    => 1,
    xid     => 0,
    flags   => 0,
    ciaddr  => '114.77.17.255',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.74.0.1',
    chaddr  => 0 x 32,
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
);

my %options = (
    53 => 6,
    54 => '211.29.132.90',
);

#
# Simple offline anaysis
#
my $file = "$FindBin::Bin/data/DHCP-NAK-SMALL.cap";
my $oDump = Net::Frame::Dump::Offline->new(
    file => $file) or BAIL_OUT( "Could not open $file" );

$oDump->start;

my $h = $oDump->next;
my $f = Net::Frame::Simple->new(
    raw        => $h->{raw},
    firstLayer => $h->{firstLayer},
    timestamp  => $h->{timestamp},
);
$f->unpack;

my $smallnak;
warning_like { $smallnak = Net::DHCP::Packet->new($f->ref->{UDP}->payload) }
    qr/too small/i, 'nak is actually a little small';

$oDump->stop;

for my $key (sort keys %values) {

    is( $smallnak->$key, $values{$key}, "Checking $key is $values{$key}" );

}

for my $key (sort keys %options) {

    is( $smallnak->getOptionValue($key), $options{$key}, "Checking $key is $options{$key}" );

}


1

#print $nak->toString;
