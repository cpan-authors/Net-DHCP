#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 15;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':ra_codes' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':dhcp_other' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':dho_codes' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':geoconf_codes' ); }

sub pack_subopt {
    my ($type, $val) = @_;
    return pack("C C a*", $type, length($val), $val);
}

subtest 'link selection suboption (5) with inet format' => sub {
    plan tests => 2;
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_LINK_SELECTION(), '10.0.0.1');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_LINK_SELECTION()),
        '10.0.0.1', 'add/get link selection round-trip');
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_LINK_SELECTION()),
        "\x0A\x00\x00\x01", 'raw link selection correct');
};

subtest 'subscriber id suboption (6) with string format' => sub {
    plan tests => 2;
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_SUBSCRIBER_ID(), 'user@isp');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_SUBSCRIBER_ID()),
        'user@isp', 'add/get subscriber id round-trip');
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_SUBSCRIBER_ID()),
        'user@isp', 'raw subscriber id correct');
};

subtest 'relay agent flags suboption (10) with byte format' => sub {
    plan tests => 2;
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_FLAGS(), '1');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_FLAGS()),
        1, 'add/get flags round-trip');
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_FLAGS()),
        "\x01", 'raw flags correct');
};

subtest 'server id override suboption (11) with inet format' => sub {
    plan tests => 2;
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_SERVER_ID_OVERRIDE(), '192.168.1.1');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_SERVER_ID_OVERRIDE()),
        '192.168.1.1', 'add/get server id override round-trip');
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_SERVER_ID_OVERRIDE()),
        "\xC0\xA8\x01\x01", 'raw server id override correct');
};

subtest 'agent id suboption (3) with hexa format' => sub {
    plan tests => 2;
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_AGENT_ID(), 'aabbccdd');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_AGENT_ID()),
        'aabbccdd', 'add/get agent id round-trip');
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_AGENT_ID()),
        "\xAA\xBB\xCC\xDD", 'raw agent id correct');
};

subtest 'structured circuit id — Cisco VLAN/Module/Port' => sub {
    plan tests => 6;
    my $p = Net::DHCP::Packet->new();

    # Build Cisco circuit-id: \x00\x04 + VLAN=10 (u16) + Module=2 (u8) + Port=3 (u8)
    my $cisco_bin = pack('C C n C C', 0x00, 0x04, 10, 2, 3);
    $p->addSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), $cisco_bin);

    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        'VLAN=10 Module=2 Port=3',
        'structured circuit-id decoded');

    # Round-trip via addSubOptionValue
    my $p2 = Net::DHCP::Packet->new();
    $p2->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(),
        'VLAN=10 Module=2 Port=3');
    is($p2->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        'VLAN=10 Module=2 Port=3',
        'structured circuit-id pack/unpack round-trip');
    is($p2->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        $cisco_bin, 'raw structured circuit-id matches');

    # Legacy hex input still works
    my $p3 = Net::DHCP::Packet->new();
    $p3->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), 'aabb');
    is($p3->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        'aabb', 'legacy hex input still works');
    is($p3->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        "\xAA\xBB", 'raw legacy hex correct');

    # Vendor string format (\x01 prefix)
    my $p4 = Net::DHCP::Packet->new();
    $p4->addSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(), "\x01switch-port-3");
    is($p4->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID()),
        'switch-port-3', 'circuit-id vendor string decoded');
};

subtest 'structured remote id — Cisco MAC' => sub {
    plan tests => 5;
    my $p = Net::DHCP::Packet->new();

    # Build Cisco remote-id: \x00\x06 + MAC (6 bytes)
    my $mac_bin = pack('C C a6', 0x00, 0x06, "\x00\x11\x22\x33\x44\x55");
    $p->addSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID(), $mac_bin);

    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
        '00:11:22:33:44:55', 'structured remote-id MAC decoded');

    # Round-trip via addSubOptionValue with MAC input
    my $p2 = Net::DHCP::Packet->new();
    $p2->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID(),
        '00:11:22:33:44:55');
    is($p2->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
        '00:11:22:33:44:55', 'structured remote-id pack/unpack round-trip');
    is($p2->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
        $mac_bin, 'raw structured remote-id matches');

    # Legacy hex input still works
    my $p3 = Net::DHCP::Packet->new();
    $p3->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID(), 'ccdd');
    is($p3->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
        'ccdd', 'legacy hex input still works for remote-id');
    is($p3->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_REMOTE_ID()),
        "\xCC\xDD", 'raw legacy hex correct for remote-id');
};

subtest 'vss suboptions (151, 152) with hexa format' => sub {
    plan tests => 2;
    my $p = Net::DHCP::Packet->new();
    $p->addSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_DHCPV4_VIRTUAL_SUBNET_SELECTION(), 'deadbeef');
    is($p->getSubOptionValue(DHO_DHCP_AGENT_OPTIONS(), RAI_DHCPV4_VIRTUAL_SUBNET_SELECTION()),
        'deadbeef', 'add/get VSS round-trip');
    is($p->getSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_DHCPV4_VIRTUAL_SUBNET_SELECTION()),
        "\xDE\xAD\xBE\xEF", 'raw VSS correct');
};

subtest 'printable-string heuristic in toString' => sub {
    plan tests => 3;
    my $p = Net::DHCP::Packet->new();

    # Hexa suboption with printable data (Agent ID with ASCII text)
    $p->addSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_AGENT_ID(), 'HelloAgent');
    my $out = $p->toString();
    like($out, qr/HelloAgent/, 'hexa suboption with printable data shown as string');

    # Hexa suboption with binary data (should stay hex)
    my $p2 = Net::DHCP::Packet->new();
    $p2->addSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_AGENT_ID(), "\xDE\xAD\xBE\xEF");
    my $out2 = $p2->toString();
    like($out2, qr/deadbeef/, 'hexa suboption with binary data shown as hex');

    # Structured circuit-id shows formatted string in toString
    my $p3 = Net::DHCP::Packet->new();
    $p3->addSubOptionRaw(DHO_DHCP_AGENT_OPTIONS(), RAI_CIRCUIT_ID(),
        pack('C C n C C', 0x00, 0x04, 5, 1, 2));
    my $out3 = $p3->toString();
    like($out3, qr/VLAN=5/, 'structured circuit-id shown formatted in toString');
};

subtest 'geoconf suboption (123) with int/byte format' => sub {
    plan tests => 5;
    my $p = Net::DHCP::Packet->new();

    # Does not croak
    eval { $p->getOptionValue(123) };
    is($@, '', 'getOptionValue(123) does not croak');

    # Meters as int (u32)
    $p->addSubOptionValue(DHO_GEOCONF(), GEO_METERS(), '100');
    is($p->getSubOptionValue(DHO_GEOCONF(), GEO_METERS()),
        100, 'add/get geoconf meters round-trip');
    is($p->getSubOptionRaw(DHO_GEOCONF(), GEO_METERS()),
        "\x00\x00\x00\x64", 'raw geoconf meters correct');

    # Floors as byte
    $p->addSubOptionValue(DHO_GEOCONF(), GEO_FLOORS(), '5');
    is($p->getSubOptionValue(DHO_GEOCONF(), GEO_FLOORS()),
        5, 'add/get geoconf floors round-trip');
    is($p->getSubOptionRaw(DHO_GEOCONF(), GEO_FLOORS()),
        "\x05", 'raw geoconf floors correct');
};
