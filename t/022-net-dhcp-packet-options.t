#!/usr/bin/env perl


use strict;
use warnings;
use Test::More tests => 26;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':ra_codes' ); }

my $foo = 'foobar';

subtest 'dhcp message type' => sub {
plan tests => 2;
my $pac = Net::DHCP::Packet->new();
$pac->setOptionValue(DHO_DHCP_MESSAGE_TYPE(), DHCPINFORM());
is($pac->getOptionValue(DHO_DHCP_MESSAGE_TYPE()), DHCPINFORM(), 'testing message type');
is($pac->getOptionRaw(DHO_DHCP_MESSAGE_TYPE()), chr(DHCPINFORM()));
};

subtest 'inet (subnet mask)' => sub {
plan tests => 8;
my $pac = Net::DHCP::Packet->new();
is($pac->getOptionValue(DHO_SUBNET_MASK()), undef, 'testing inet format');
$pac->setOptionValue(DHO_SUBNET_MASK(), "255.255.255.0");
is($pac->getOptionValue(DHO_SUBNET_MASK()), "255.255.255.0");
is($pac->getOptionRaw(DHO_SUBNET_MASK()), "\xFF\xFF\xFF\0");
$pac->setOptionRaw(DHO_SUBNET_MASK(), "\xFF\xFF\xFF\0");
is($pac->getOptionValue(DHO_SUBNET_MASK()), "255.255.255.0");
is($pac->getOptionRaw(DHO_SUBNET_MASK()), "\xFF\xFF\xFF\0");
eval { $pac->setOptionValue(DHO_SUBNET_MASK()); };
like( $@, qr/exactly one value expected/);
eval { $pac->setOptionValue(DHO_SUBNET_MASK(), undef); };
like( $@, qr/exactly one value expected/);
eval { $pac->setOptionValue(DHO_SUBNET_MASK(), "255.255.255.0 255.255.255.0"); };
like( $@, qr/exactly one value expected/);
};

subtest 'inets (name servers)' => sub {
plan tests => 4;
my $pac = Net::DHCP::Packet->new();
is($pac->getOptionValue(DHO_NAME_SERVERS()), undef, "testing inets format");
$pac->setOptionValue(DHO_NAME_SERVERS(), '1.2.3.15, 4.5.6.14');
is($pac->getOptionRaw(DHO_NAME_SERVERS()), "\1\2\3\x0F\4\5\6\x0E");
is($pac->getOptionValue(DHO_NAME_SERVERS()), '1.2.3.15, 4.5.6.14');
$pac->setOptionValue(DHO_NAME_SERVERS());
is($pac->getOptionValue(DHO_NAME_SERVERS()), undef);
};

subtest 'inets2 (static routes)' => sub {
plan tests => 7;
my $pac = Net::DHCP::Packet->new();
is($pac->getOptionValue(DHO_STATIC_ROUTES()), undef, "testing inets2 format");
$pac->setOptionValue(DHO_STATIC_ROUTES(), '1.2.3.15, 4.5.6.14');
is($pac->getOptionRaw(DHO_STATIC_ROUTES()), "\1\2\3\x0F\4\5\6\x0E");
is($pac->getOptionValue(DHO_STATIC_ROUTES()), '1.2.3.15, 4.5.6.14');
$pac->setOptionValue(DHO_STATIC_ROUTES());
is($pac->getOptionValue(DHO_STATIC_ROUTES()), undef);
eval { $pac->setOptionValue(DHO_STATIC_ROUTES()); };
ok( ! $@ );
eval { $pac->setOptionValue(DHO_STATIC_ROUTES(), undef); };
ok( ! $@ );
eval { $pac->setOptionValue(DHO_STATIC_ROUTES(), "255.255.255.0"); };
like( $@, qr/only pairs of values expected/);
};

subtest 'int (renewal time)' => sub {
plan tests => 3;
my $pac = Net::DHCP::Packet->new();
$pac->setOptionValue(DHO_DHCP_RENEWAL_TIME(), 0x12345678);
is($pac->getOptionValue(DHO_DHCP_RENEWAL_TIME()), 0x12345678, "testing int format");
is($pac->getOptionRaw(DHO_DHCP_RENEWAL_TIME()), "\x12\x34\x56\x78");
eval { $pac->setOptionValue(DHO_DHCP_RENEWAL_TIME(), undef); } ;
like( $@, qr/exactly one value expected/);
};

subtest 'short (interface MTU)' => sub {
plan tests => 3;
my $pac = Net::DHCP::Packet->new();
$pac->setOptionValue(DHO_INTERFACE_MTU(), 0x12345678);
is($pac->getOptionValue(DHO_INTERFACE_MTU()), 0x5678,     'testing short format 0x5678');
is($pac->getOptionRaw(  DHO_INTERFACE_MTU()), "\x56\x78", 'testing short format \x56\x78');
eval { $pac->setOptionValue(DHO_INTERFACE_MTU(), undef); };
like( $@, qr/exactly one value expected/, 'testing short format undef');
};

subtest 'byte (default TTL)' => sub {
plan tests => 3;
my $pac = Net::DHCP::Packet->new();
$pac->setOptionValue(DHO_DEFAULT_TCP_TTL(), 0x12345678);
is($pac->getOptionValue(DHO_DEFAULT_TCP_TTL()), 0x78,     'testing byte format 0x78');
is($pac->getOptionRaw(  DHO_DEFAULT_TCP_TTL()), "\x78",   'testing byte format \x78');
eval { $pac->setOptionValue(DHO_DEFAULT_TCP_TTL(), undef); };
like( $@, qr/exactly one value expected/, 'testing byte format undef');
};

subtest 'bytes (parameter request list)' => sub {
plan tests => 4;
my $pac = Net::DHCP::Packet->new();
is($pac->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST()), undef, 'testing bytes format is init\'d as empty');
$pac->setOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST(),  "1 3 5 1278 ".0xFFFFFFFF,);
is($pac->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST()), '1, 3, 5, 254, 255', 'testing bytes format with some integers, a wrap and a hex');
is($pac->getOptionRaw(DHO_DHCP_PARAMETER_REQUEST_LIST()), "\x01\x03\x05\xFE\xFF", 'testing bytes format as above, using hex format');
$pac->setOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST(), undef);
is($pac->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST()), q(), 'testing bytes format, clearing with undef');
};

subtest 'string (TFTP server)' => sub {
plan tests => 3;
my $pac = Net::DHCP::Packet->new();
$pac->setOptionValue(DHO_TFTP_SERVER(), $foo);
is($pac->getOptionValue(DHO_TFTP_SERVER()), $foo, "testing string format");
is($pac->getOptionRaw(DHO_TFTP_SERVER()), $foo);
eval { $pac->setOptionValue(DHO_TFTP_SERVER(), undef); };
is($pac->getOptionRaw(DHO_TFTP_SERVER()), undef);
};

my $pac = Net::DHCP::Packet->new();
# test for 'relays' format
#my @relay = ( 1 => 'foo', 2 => 'bar', 3 => 'baz');
#$pac->setOptionValue(DHO_DHCP_AGENT_OPTIONS(), @relay);
#my @relay2 = $pac->getOptionValue(DHO_DHCP_AGENT_OPTIONS());
#is_deeply(\@relay2, \@relay, "testing relays format");

subtest 'option removal' => sub {
plan tests => 12;
my $pac = Net::DHCP::Packet->new();
$pac->setOptionValue(DHO_DEFAULT_TCP_TTL(), 0x78);
$pac->setOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST(),  "1 3 5 254 255");
$pac->setOptionValue(DHO_TFTP_SERVER(), $foo);
is($pac->getOptionValue(DHO_TFTP_SERVER()), $foo, "testing option removal");
is($pac->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST()), '1, 3, 5, 254, 255');
is($pac->getOptionValue(DHO_DEFAULT_TCP_TTL()), 0x78);
$pac->removeOption(DHO_DHCP_PARAMETER_REQUEST_LIST());
is($pac->getOptionValue(DHO_TFTP_SERVER()), $foo);
is($pac->getOptionRaw(DHO_DHCP_PARAMETER_REQUEST_LIST()), undef);
is($pac->getOptionValue(DHO_DEFAULT_TCP_TTL()), 0x78);
$pac->removeOption(DHO_DHCP_PARAMETER_REQUEST_LIST());
$pac->removeOption(DHO_STATIC_ROUTES());
$pac->removeOption(DHO_TFTP_SERVER());
is($pac->getOptionRaw(DHO_TFTP_SERVER()), undef);
is($pac->getOptionRaw(DHO_DHCP_PARAMETER_REQUEST_LIST()), undef);
is($pac->getOptionValue(DHO_DEFAULT_TCP_TTL()), 0x78);
$pac->removeOption(DHO_DEFAULT_TCP_TTL());
is($pac->getOptionRaw(DHO_TFTP_SERVER()), undef);
is($pac->getOptionRaw(DHO_DHCP_PARAMETER_REQUEST_LIST()), undef);
is($pac->getOptionRaw(DHO_DEFAULT_TCP_TTL()), undef);
};

subtest 'suboption values and removal' => sub {
plan tests => 7;
my $p = Net::DHCP::Packet->new();
$p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "aabb");
is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
    "\xAA\xBB", 'getSubOptionRaw after addSubOptionValue hexa');
is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
    'aabb', 'getSubOptionValue round trip hexa');
is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_LINK_SELECTION()),
    undef, 'getSubOptionValue for missing suboption');
$p->removeSubOption(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID());
is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
    undef, 'after removeSubOption, raw is undef');
$p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "aabb");
$p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID(), "ccdd");
is(scalar(@{$p->{sub_options_order}->{DHO_DHCP_AGENT_OPTIONS()}}),
    2, 'two suboptions in order');
$p->removeSubOption(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID());
is(scalar(@{$p->{sub_options_order}->{DHO_DHCP_AGENT_OPTIONS()}}),
    1, 'one suboption left after remove');
is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
    'ccdd', 'other suboption intact');
};

subtest 'suboption validation croaks' => sub {
plan tests => 4;
my $p = Net::DHCP::Packet->new();
$p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "aabb");

eval { $p->getSubOptionValue(90, 1) };
like($@, qr/unknown format for code/, 'getSubOptionValue croaks for unknown option code');

eval { $p->getSubOptionValue(DHO_SUBNET_MASK(), 1) };
like($@, qr/not a suboption parameter/, 'getSubOptionValue croaks for non-suboption code');

eval { $p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), 999) };
like($@, qr/suboption.*not defined/, 'getSubOptionValue croaks for undefined suboption');

eval { $p->getSubOptionValue(DHO_VENDOR_ENCAPSULATED_OPTIONS(), 1) };
like($@, qr/suboption.*not defined/, 'getSubOptionValue croaks for undefined option43 suboption');
};

# getSubOptionValue and removeSubOption
{
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "aabb");
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        "\xAA\xBB", 'getSubOptionRaw after addSubOptionValue hexa');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        'aabb', 'getSubOptionValue round trip hexa');

    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_LINK_SELECTION()),
        undef, 'getSubOptionValue for missing suboption');

    $p->removeSubOption(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID());
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        undef, 'after removeSubOption, raw is undef');

    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "aabb");
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID(), "ccdd");
    is(scalar(@{$p->{sub_options_order}->{DHO_DHCP_AGENT_OPTIONS()}}),
        2, 'two suboptions in order');
    $p->removeSubOption(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID());
    is(scalar(@{$p->{sub_options_order}->{DHO_DHCP_AGENT_OPTIONS()}}),
        1, 'one suboption left after remove');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
        'ccdd', 'other suboption intact');
}

# getSubOptionValue validation croaks
{
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "aabb");

    eval { $p->getSubOptionValue(90, 1) };
    like($@, qr/unknown format for code/, 'getSubOptionValue croaks for unknown option code');

    eval { $p->getSubOptionValue(DHO_SUBNET_MASK(), 1) };
    like($@, qr/not a suboption parameter/, 'getSubOptionValue croaks for non-suboption code');

    eval { $p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), 999) };
    like($@, qr/suboption.*not defined/, 'getSubOptionValue croaks for undefined suboption');

    eval { $p->getSubOptionValue(DHO_VENDOR_ENCAPSULATED_OPTIONS(), 1) };
    like($@, qr/suboption.*not defined/, 'getSubOptionValue croaks for undefined option43 suboption');
}

