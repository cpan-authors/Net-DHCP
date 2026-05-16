#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 4;
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
        xid     => 2011560758,
        secs    => 63,
        flags   => 0,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '10.53.0.1',
        chaddr  => 'c40415bda86200000000000000000000',
        sname   => '',
        file    => '',
        isDhcp  => 1,
        padding => '',
    }, {
        53 => 1,
        57 => 1500,
        55 => '1, 2, 3, 6, 7, 12, 15, 54, 122',
    },
];

# packet 2
push @data, [
    'OFFER',
    {
        op      => BOOTREPLY,
        htype   => 1,
        hlen    => 6,
        hops    => 1,
        xid     => 2011560758,
        secs    => 63,
        flags   => 0,
        ciaddr  => '0.0.0.0',
        yiaddr  => '10.214.98.138',
        siaddr  => '211.29.132.141',
        giaddr  => '10.53.0.1',
        chaddr  => 'c40415bda86200000000000000000000',
        sname   => '',
        file    => '',
        isDhcp  => 1,
        padding => '',
    }, {
        53 => 2,
         1  => '255.255.192.0',
         2  => 36000,
         3  => '10.214.64.1',
         6  => '198.142.0.51, 211.29.132.12, 198.142.235.14',
         7  => '211.29.152.26',
        15  => 'optusnet.com.au',
        51 => 3600,
        54 => '211.29.132.90',
    }
];

#
# Simple offline anaysis
#
my $file = "$FindBin::Bin/data/DHCP-O60-O43-O82.cap";
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

