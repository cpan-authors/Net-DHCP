#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 3;
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants', ':bootp_codes'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my %values = (
    op      => BOOTREPLY,
    htype   => 1,
    hlen    => 6,
    hops    => 1,
    xid     => 2003947397,
    secs    => 10,
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '10.10.8.235',
    siaddr  => '172.22.178.234',
    giaddr  => '10.10.8.240',
    chaddr  => '000e8611c07500000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
);

my %options = (
    53  => 2,
    1   => '255.255.255.0',
    54  => '172.22.178.234',
    51  => 43200,
    3   => '10.10.8.254',
    6   => '143.209.4.1, 143.209.5.1',
    66  => '172.22.178.234',
    120 => '172.22.178.234',
    61  => 'nathan1clientid',
    # 90  => auth
    # 82  => agent
);

#
# Simple offline anaysis
#
my $file = "$FindBin::Bin/data/DHCP-O90-O120.cap";
my $oDump = Net::Frame::Dump::Offline->new(
    file => $file) or BAIL_OUT( "Could not open $file" );

$oDump->start;

subtest 'OFFER with options 90/120' => sub {

my $h = $oDump->next;
my $f = Net::Frame::Simple->new(
    raw        => $h->{raw},
    firstLayer => $h->{firstLayer},
    timestamp  => $h->{timestamp},
);
$f->unpack;

my $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload);

for my $key (sort keys %values) {
    is( $dhcp->$key, $values{$key}, "Checking $key is $values{$key}" );
}

for my $key (sort keys %options) {
    is( $dhcp->getOptionValue($key), $options{$key}, "Checking $key is $options{$key}" );
}

};

$oDump->stop;

1

