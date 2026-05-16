#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants', ':bootp_codes'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my @data;

# packet 1
push @data, [
    'DISCOVER',
    {
        op      => BOOTREQUEST,
        htype   => 1,
        hlen    => 6,
        hops    => 1,
        xid     => 9179,
        secs    => 0,
        flags   => 32768,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '192.168.1.1',
        chaddr  => 'cc030ba8000000000000000000000000',
        sname   => '',
        file    => '',
        isDhcp  => 1,
    }, {
        53 => 1,
        57 => 1152,
        61 => 'cisco-cc03.0ba8.0000-Fa0/0',
        12 => 'PC1',
        55 => '1, 6, 15, 44, 3, 33, 150, 43',
    },
];

# packet 2
push @data, [
    'OFFER',
    {
        op      => BOOTREPLY,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => 9179,
        secs    => 0,
        flags   => 32768,
        ciaddr  => '0.0.0.0',
        yiaddr  => '192.168.1.3',
        siaddr  => '0.0.0.0',
        giaddr  => '192.168.1.1',
        chaddr  => 'cc030ba8000000000000000000000000',
        sname   => '',
        file    => '',
        isDhcp  => 1,
    }, {
        53 => 2,
        54 => '192.168.0.2',
        51 => 86291,
        58 => 43145,
        59 => 75504,
        12 => 'PC1',
         1 => '255.255.255.0',
         3 => '192.168.1.1',
         6 => '1.1.1.1, 2.2.2.2',
    },
];

# packet 3
push @data, [
    'REQUEST',
    {
        op      => BOOTREQUEST,
        htype   => 1,
        hlen    => 6,
        hops    => 1,
        xid     => 9179,
        secs    => 0,
        flags   => 32768,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '192.168.1.1',
        chaddr  => 'cc030ba8000000000000000000000000',
        sname   => '',
        file    => '',
        isDhcp  => 1,
    }, {
        53 => 3,
        54 => '192.168.0.2',
        50 => '192.168.1.3',
        51 => 86291,
        57 => 1152,
        61 => 'cisco-cc03.0ba8.0000-Fa0/0',
        12 => 'PC1',
        55 => '1, 6, 15, 44, 3, 33, 150, 43',
    },
];

# packet 4
push @data, [
    'ACK',
    {
        op      => BOOTREPLY,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => 9179,
        secs    => 0,
        flags   => 32768,
        ciaddr  => '0.0.0.0',
        yiaddr  => '192.168.1.3',
        siaddr  => '0.0.0.0',
        giaddr  => '192.168.1.1',
        chaddr  => 'cc030ba8000000000000000000000000',
        sname   => '',
        file    => '',
        isDhcp  => 1,
    }, {
        53 => 5,
        54 => '192.168.0.2',
        51 => 86400,
        58 => 43200,
        59 => 75600,
        12 => 'PC1',
         1 => '255.255.255.0',
         3 => '192.168.1.1',
         6 => '1.1.1.1, 2.2.2.2',
    },
];

#
# Simple offline analysis
#
my $file = "$FindBin::Bin/data/DHCP_Inter_VLAN.cap";
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

my $foo = shift @data;
my $name = $foo->[0];
my %values = %{$foo->[1]};
my %options = %{$foo->[2]};

subtest $name => sub {

my $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload);

for my $key (sort keys %values) {
    is( $dhcp->$key, $values{$key}, "Checking $key is $values{$key}" );
}

for my $key (sort keys %options) {
    is( $dhcp->getOptionValue($key), $options{$key}, "Checking $key is $options{$key}" );
}

};

}

$oDump->stop;


1
