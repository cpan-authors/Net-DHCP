#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants' ); }

subtest 'marshall validation' => sub {
plan tests => 4;

my $pac;

eval {
  $pac = Net::DHCP::Packet->new('');
};
like( $@, qr/marshall: packet too small/, "packet too small");

eval {
  $pac = Net::DHCP::Packet->new("\0" x 2000);
};
like( $@, qr/marshall: packet too big/, 'packet too big');

eval {
  $pac = Net::DHCP::Packet->new( Net::DHCP::Packet->new()->serialize());
};
ok( ! $@, 'verifying default packet');

my $pac_without_option_end = pack('H*',
"0101060012345678000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000006382536300000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"000000000000000000000000"
);
eval {
  $pac = Net::DHCP::Packet->new($pac_without_option_end);
};
like( $@, qr/marshall: unexpected end of options/, 'marshall: unexpected end of options');
};

subtest 'odd number of arguments' => sub {
plan tests => 1;
eval {
  my $pac = Net::DHCP::Packet->new(54, "foo", 55);
};
like( $@, qr/odd number of arguments/, 'new: odd number of arguments');
};

subtest 'serialize validation' => sub {
plan tests => 1;
my $pac = Net::DHCP::Packet->new();
$pac->padding("\0" x 2000);
eval {
  $pac->serialize();
};
like($@, qr/serialize: packet too big/, "serialize: packet too big");
};

subtest 'DHO_DHCP_MAX_MESSAGE_SIZE conformance' => sub {
plan tests => 4;
my %options = ( DHO_DHCP_MAX_MESSAGE_SIZE() => 200);
my $ref_pac = pack("H*",
"0101060012345678000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"00000000000000000000000063825363ff000000000000000000000000000000".
"0000000000000000000000000000000000000000000000000000000000000000".
"00000000000000000000000000000000"
);
my $pac = Net::DHCP::Packet->new($ref_pac);
eval {
  $pac->serialize(\%options);
};
ok( ! $@, "DHO_DHCP_MAX_MESSAGE_SIZE too small");
$options{DHO_DHCP_MAX_MESSAGE_SIZE()} = 2000;
eval {
  $pac->serialize(\%options);
};
ok( ! $@, "DHO_DHCP_MAX_MESSAGE_SIZE too big");
$options{DHO_DHCP_MAX_MESSAGE_SIZE()} = 305;
eval {
  $pac->serialize(\%options);
};
ok( ! $@, "DHO_DHCP_MAX_MESSAGE_SIZE is ok");
$options{DHO_DHCP_MAX_MESSAGE_SIZE()} = 302;
eval {
  $pac->serialize(\%options);
};
like($@, qr/serialize: message is bigger than allowed/, "serialize: packet too big");
};
