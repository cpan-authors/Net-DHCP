#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 40;
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my @data;

# packet 1
push @data, [
{
    htype   => 1,
    hlen    => 6,
    hops    => 1,
    xid     => 190347688,
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '10.68.0.1',
    chaddr  => '200cc8e2fa3100000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53 => 1,
    # 55 => 1,
    # 60 => 1,
    # 43 => 1,
    # 61 => 1,
    # 57 => 1,
    # 82 => 1,
},
];

# packet 2
push @data, [
{
    htype   => 1,
    hlen    => 6,
    hops    => 1,
    xid     => 190347688,
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '10.219.62.18',
    siaddr  => '211.29.132.141',
    giaddr  => '10.68.0.1',
    chaddr  => '200cc8e2fa3100000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '',
}, {
    53  => 2,
    54  => '211.29.132.90',
    51  => 3600,
    1   => '255.255.192.0',
    2   => 36000,
    3   => '10.219.0.1',
    6   => '198.142.0.51, 211.29.132.12, 198.142.235.14',
    7   => '211.29.152.26',
    15  => 'optusnet.com.au',
    # 122 =>
    # 82  =>
}
];

#
# Simple offline anaysis
#
my $file = "$FindBin::Bin/data/DHCP-O122-O82.cap";
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

my $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload);

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

