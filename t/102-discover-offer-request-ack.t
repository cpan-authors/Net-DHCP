#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 81;
use Test::Warn qw( warning_like );
use FindBin ();

BEGIN { use_ok('Net::DHCP::Packet'); }
BEGIN { use_ok('Net::DHCP::Constants', ':htype_codes', ':dhcp_message',':dhcp_hashes' ); }

use Net::Frame::Simple ();
use Net::Frame::Dump::Offline;

my @data;

# DISCOVER
push @data, [
{
    htype   => HTYPE_ETHER,
    hlen    => 6,
    hops    => 0,
    xid     => '15645',
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '0.0.0.0',
    chaddr  => '000b8201fc4200000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '00000000000000',
}, {
    53 => DHCPDISCOVER,
    61 => '000b8201fc42',
    50 => '0.0.0.0',
    55 => '1, 3, 6, 42',
},
];

# OFFER
push @data, [
{
    htype   => HTYPE_ETHER,
    hlen    => 6,
    hops    => 0,
    xid     => '15645',
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '192.168.0.10',
    siaddr  => '192.168.0.1',
    giaddr  => '0.0.0.0',
    chaddr  => '000b8201fc4200000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '0000000000000000000000000000000000000000000000000000',
}, {
    53 => DHCPOFFER,
    1  => '255.255.255.0',
    58 => 1800,
    59 => 3150,
    51 => 3600,
    54 => '192.168.0.1',
}
];

# REQUEST
push @data, [
{
    htype   => HTYPE_ETHER,
    hlen    => 6,
    hops    => 0,
    xid     => '15646',
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '0.0.0.0',
    siaddr  => '0.0.0.0',
    giaddr  => '0.0.0.0',
    chaddr  => '000b8201fc4200000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '00',
}, {
    53 => DHCPREQUEST,
    61 => '000b8201fc42',
    50 => '192.168.0.10',
    54 => '192.168.0.1',
    55 => '1, 3, 6, 42',
}
];

# ACK
push @data, [
{
    htype   => HTYPE_ETHER,
    hlen    => 6,
    hops    => 0,
    xid     => '15646',
    flags   => 0,
    ciaddr  => '0.0.0.0',
    yiaddr  => '192.168.0.10',
    siaddr  => '0.0.0.0',
    giaddr  => '0.0.0.0',
    chaddr  => '000b8201fc4200000000000000000000',
    sname   => '',
    file    => '',
    isDhcp  => 1,
    padding => '0000000000000000000000000000000000000000000000000000',
}, {
    53 => DHCPACK,
    1  => '255.255.255.0',
    58 => 1800,
    59 => 3150,
    51 => 3600,
    54 => '192.168.0.1',
},
];

#
# Simple offline anaysis
#
my $file = "$FindBin::Bin/data/DHCP-DISCOVER-OFFER-REQUEST-ACK.cap";
my $oDump = Net::Frame::Dump::Offline->new( file => $file
    ) or BAIL_OUT( "Could not open $file" );

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
    my $foo =  shift @data or last;
    %values  = %{$foo->[0]};
    %options = %{$foo->[1]};
}

my $len = length($f->ref->{UDP}->payload);

my $dhcp;

if ($len < 300) {
  warning_like { $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload) }
     qr/too small/i, 'nak is actually a little small';
}
else {
  $dhcp = Net::DHCP::Packet->new($f->ref->{UDP}->payload);
}

for my $key (sort keys %values) {


    is( ($key eq 'padding' ? unpack('H*', $dhcp->$key ) : $dhcp->$key ), $values{$key}, "Checking $key is $values{$key}" );

}

for my $key (sort keys %options) {

    is( $dhcp->getOptionValue($key), $options{$key}, "Checking $REV_DHO_CODES{$key} is $options{$key}" );

}

# print $dhcp->toString;

} # while (my $h

# print "count: $count\n";

$oDump->stop;


1

