#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 8;
use Test::Warn qw( warning_like );
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants', ':bootp_codes'); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my @data;

# packet 1 — DHCPINFORM 3788063565
push @data, [
    'DHCPINFORM (3788063565)',
    {
        op      => BOOTREQUEST,
        htype   => 0,
        hlen    => 0,
        hops    => 0,
        xid     => '3788063565',
        secs    => 0,
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

# packet 2 — DHCPLEASEACTIVE
push @data, [
    'DHCPLEASEACTIVE',
    {
        op      => BOOTREPLY,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => '3788063565',
        secs    => 0,
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

# packet 3 — DHCPINFORM 3804840781
push @data, [
    'DHCPINFORM (3804840781)',
    {
        op      => BOOTREQUEST,
        htype   => 0,
        hlen    => 0,
        hops    => 0,
        xid     => '3804840781',
        secs    => 0,
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

# packet 4 — DHCPLEASEUNASSIGNED
push @data, [
    'DHCPLEASEUNASSIGNED',
    {
        op      => BOOTREPLY,
        htype   => 0,
        hlen    => 0,
        hops    => 0,
        xid     => '3804840781',
        secs    => 0,
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

# packet 5 — DHCPINFORM 3821617997
push @data, [
    'DHCPINFORM (3821617997)',
    {
        op      => BOOTREQUEST,
        htype   => 0,
        hlen    => 0,
        hops    => 0,
        xid     => '3821617997',
        secs    => 0,
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

# packet 6 — DHCPLEASEUNKNOWN
push @data, [
    'DHCPLEASEUNKNOWN',
    {
        op      => BOOTREPLY,
        htype   => 0,
        hlen    => 0,
        hops    => 0,
        xid     => '3821617997',
        secs    => 0,
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

my $dhcp;
warning_like { $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload) }
    qr/too small/i, 'packet is actually a little small';

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

