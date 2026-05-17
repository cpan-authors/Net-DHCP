#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants', ':bootp_codes'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my %tests = (

# DHCPINFORM from 10.0.41.30
'699835726:8:10.0.41.30' => ['INFORM', {
    op      => BOOTREQUEST,
    htype   => 1,
    hlen    => 6,
    hops    => 0,
    xid     => 699835726,
    secs    => 2560,
    flags   => 32768,
    ciaddr  => '10.0.41.30',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '0.0.0.0',
    chaddr  => '00000000000000000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
}, {
    53 => 8,
}],

# relayed DISCOVER with User-Class option 77
'2279704935:1:0.0.0.0' => ['DISCOVER', {
    op      => BOOTREQUEST,
    htype   => 1,
    hlen    => 6,
    hops    => 1,
    xid     => 2279704935,
    secs    => 0,
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '192.168.60.1',
    chaddr  => '000c2967427a00000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
}, {
    53 => 1,
    12 => 'dhcptestclient',
    55 => '1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42, 77',
     77 => 'markku',
}],

# relayed OFFER with siaddr set
'2279704935:2:0.0.0.0' => ['OFFER', {
    op      => BOOTREPLY,
    htype   => 1,
    hlen    => 6,
    hops    => 0,
    xid     => 2279704935,
    secs    => 0,
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '192.168.60.100',
    siaddr  => '10.0.41.30',
    giaddr  => '192.168.60.1',
    chaddr  => '000c2967427a00000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
}, {
    53 => 2,
     1 => '255.255.255.0',
    58 => 60,
    59 => 105,
    51 => 120,
    54 => '10.0.41.30',
     3 => '192.168.60.1',
     6 => '1.1.1.1, 1.0.0.1',
}],

# DHCPRELEASE
'3510729295:7:192.168.60.100' => ['RELEASE', {
    op      => BOOTREQUEST,
    htype   => 1,
    hlen    => 6,
    hops    => 0,
    xid     => 3510729295,
    secs    => 0,
    flags   => 0,
    ciaddr  => '192.168.60.100',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '0.0.0.0',
    chaddr  => '000c2967427a00000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
}, {
    53 => 7,
    54 => '10.0.41.30',
    12 => 'dhcptestclient',
     77 => 'markku',
}],

);

#
# Simple offline analysis
#
my $file = "$FindBin::Bin/data/dhcpfo.pcapng";
my $oDump = Net::Frame::Dump::Offline->new(
    file => $file) or BAIL_OUT( "Could not open $file" );

$oDump->start;

while (my $h = $oDump->next) {

my $f = Net::Frame::Simple->new(
    raw        => $h->{raw},
    firstLayer => $h->{firstLayer},
    timestamp  => $h->{timestamp},
);
$f->unpack;

# skip non-UDP (TCP, ARP, etc.)
next unless $f->ref->{UDP};

my $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload);
my $key  = join(':', $dhcp->xid, $dhcp->getOptionValue(53), $dhcp->ciaddr);
next unless exists $tests{$key};

my ($name, $vref, $oref) = @{ delete $tests{$key} };

subtest $name => sub {

for my $k (sort keys %$vref) {
    is( $dhcp->$k, $vref->{$k}, "Checking $k is $vref->{$k}" );
}

for my $k (sort keys %$oref) {
    is( $dhcp->getOptionValue($k), $oref->{$k}, "Checking $k is $oref->{$k}" );
}

};

last unless scalar keys %tests;

}

$oDump->stop;


1
