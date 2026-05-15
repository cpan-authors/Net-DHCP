#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 98;
use Test::Warn qw( warning_like );
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my @data;

# packet 1
push @data, [
{
    htype   => 0,
    hlen    => 0,
    hops    => 0,
    xid     => '3788063565',
    flags   => 0,
    ciaddr  => '1.1.1.2',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.10.39.14',
    chaddr  => '00000000000000000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 10,
},
];

# packet 2
push @data, [
{
    htype   => 1,
    hlen    => 6,
    hops    => 0,
    xid     => '3788063565',
    flags   => 0,
    ciaddr  => '1.1.1.2',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.10.39.14',
    chaddr  => '02020101010200000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 13,
}
];

# packet 3
push @data, [
{
    htype   => 0,
    hlen    => 0,
    hops    => 0,
    xid     => '3804840781',
    flags   => 0,
    ciaddr  => '1.1.1.3',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.10.39.14',
    chaddr  => '00000000000000000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 10,
}
];

# packet 4
push @data, [
{
    htype   => 0,
    hlen    => 0,
    hops    => 0,
    xid     => '3804840781',
    flags   => 0,
    ciaddr  => '1.1.1.3',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.10.39.14',
    chaddr  => '00000000000000000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 11,
},
];

# packet 5
push @data, [
{
    htype   => 0,
    hlen    => 0,
    hops    => 0,
    xid     => '3821617997',
    flags   => 0,
    ciaddr  => '1.1.1.11',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.10.39.14',
    chaddr  => '00000000000000000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 10,
}
];

# packet 6
push @data, [
{
    htype   => 0,
    hlen    => 0,
    hops    => 0,
    xid     => '3821617997',
    flags   => 0,
    ciaddr  => '1.1.1.11',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.10.39.14',
    chaddr  => '00000000000000000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 12,
}
];

#
# Simple offline anaysis
#
my $file = "$FindBin::Bin/data/DHCP_MessageType_10_11_12_13.cap";
my $oDump = Net::Frame::Dump::Offline->new(
    file => $file) or BAIL_OUT( "Could not open $file" );

$oDump->start;

my $count = 0;

while (my $h = $oDump->next) {

$count++;

my $f = Net::Frame::Simple->new(
    raw        => $h->{raw},
    firstLayer => $h->{firstLayer},
    timestamp  => $h->{timestamp},
);
$f->unpack;

my (%values,%options);

{
    my $foo =  shift @data;
    %values  = %{$foo->[0]};
    %options = %{$foo->[1]};
}

my $dhcp;
warning_like { $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload) }
    qr/too small/i, 'packet is actually a little small';

for my $key (sort keys %values) {

    is( $dhcp->$key, $values{$key}, "Checking $key is $values{$key}" );

}

for my $key (sort keys %options) {

    is( $dhcp->getOptionValue($key), $options{$key}, "Checking $key is $options{$key}" );

}

# print $dhcp->toString;

}

# print "count: $count\n";

$oDump->stop;


1

