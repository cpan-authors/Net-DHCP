#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;
use Net::DHCP::Packet;
use Net::DHCP::Constants qw(:DEFAULT :dhcp_other :dhcp_hashes %SUBOPTION_FORMATS);
use Net::DHCP::Packet::IPv4Utils qw(:all);

sub build_overload_pkt {
    my ($sname_opt_code, $sname_opt_val, $file_opt_code, $file_opt_val, $overload_val) = @_;
    $overload_val //= 3;

    my $sname_body = pack('C', $sname_opt_code)
                  . pack('C', length($sname_opt_val))
                  . $sname_opt_val
                  . pack('C', DHO_END());
    my $sname = "\x00" . $sname_body;
    $sname .= "\x00" x (64 - length($sname)) if length($sname) < 64;

    my $file_body = pack('C', $file_opt_code)
                  . pack('C', length($file_opt_val))
                  . $file_opt_val
                  . pack('C', DHO_END());
    my $file = "\x00" . $file_body;
    $file .= "\x00" x (128 - length($file)) if length($file) < 128;

    my $opt_area = MAGIC_COOKIE()
                 . pack('C', DHO_DHCP_MESSAGE_TYPE())
                 . pack('C', 1)
                 . pack('C', DHCPACK())
                 . pack('C', DHO_DHCP_OPTION_OVERLOAD())
                 . pack('C', 1)
                 . pack('C', $overload_val)
                 . pack('C', DHO_END());

    my $pkt = pack('C C C C N n n a4 a4 a4 a4 a16',
        BOOTREPLY(), HTYPE_ETHER(), ETHERNET_MAC_LEN(), 0,
        0x12345678, 0, 0,
        NULL_IP, NULL_IP, NULL_IP, NULL_IP,
        "\x00" x 16
    ) . $sname . $file . $opt_area;

    $pkt .= "\x00" x (300 - length($pkt)) if length($pkt) < 300;
    return $pkt;
}

subtest 'both fields overloaded' => sub {
    plan tests => 6;
    my $bin = build_overload_pkt(
        DHO_HOST_NAME(), 'hello',
        DHO_DOMAIN_NAME(), 'example.com',
        3
    );
    my $p = Net::DHCP::Packet->new($bin);

    is($p->getOptionValue(DHO_HOST_NAME()), 'hello', 'hostname extracted from sname');
    is($p->getOptionValue(DHO_DOMAIN_NAME()), 'example.com', 'domain extracted from file');
    is($p->getOptionRaw(DHO_DHCP_OPTION_OVERLOAD()), undef, 'option 52 removed');
    is($p->sname(), '', 'sname cleared after overload');
    is($p->file(), '', 'file cleared after overload');
    is($p->getOptionValue(DHO_DHCP_MESSAGE_TYPE()), DHCPACK(), 'main options intact');
};

subtest 'file-only overload' => sub {
    plan tests => 3;
    my $bin = build_overload_pkt(
        DHO_HOST_NAME(), 'hello',
        DHO_DOMAIN_NAME(), 'example.com',
        1  # bit 0 = file only
    );
    my $p = Net::DHCP::Packet->new($bin);

    is($p->getOptionValue(DHO_DOMAIN_NAME()), 'example.com', 'domain extracted from file');
    is($p->getOptionRaw(DHO_DHCP_OPTION_OVERLOAD()), undef, 'option 52 removed');
    is($p->file(), '', 'file cleared after overload');
};

subtest 'sname-only overload' => sub {
    plan tests => 3;
    my $bin = build_overload_pkt(
        DHO_HOST_NAME(), 'hello',
        DHO_DOMAIN_NAME(), 'example.com',
        2  # bit 1 = sname only
    );
    my $p = Net::DHCP::Packet->new($bin);

    is($p->getOptionValue(DHO_HOST_NAME()), 'hello', 'hostname extracted from sname');
    is($p->getOptionRaw(DHO_DHCP_OPTION_OVERLOAD()), undef, 'option 52 removed');
    is($p->sname(), '', 'sname cleared after overload');
};

subtest 'no overload (regression)' => sub {
    plan tests => 4;
    my $p = Net::DHCP::Packet->new(
        DHO_DHCP_MESSAGE_TYPE() => DHCPACK(),
        DHO_HOST_NAME() => 'hello',
    );
    my $bin = $p->serialize();
    my $p2 = Net::DHCP::Packet->new($bin);

    is($p2->getOptionValue(DHO_HOST_NAME()), 'hello', 'hostname unchanged');
    is($p2->getOptionValue(DHO_DHCP_MESSAGE_TYPE()), DHCPACK(), 'msg type unchanged');
    is($p2->getOptionRaw(DHO_DHCP_OPTION_OVERLOAD()), undef, 'no option 52');
    is($p2->sname(), '', 'sname unchanged (empty default)');
};

subtest 'round-trip with overload' => sub {
    plan tests => 4;
    my $bin = build_overload_pkt(
        DHO_HOST_NAME(), 'hello',
        DHO_DOMAIN_NAME(), 'example.com',
        3
    );
    my $p = Net::DHCP::Packet->new($bin);

    my $rebinned = $p->serialize();
    my $p2 = Net::DHCP::Packet->new($rebinned);

    is($p2->getOptionValue(DHO_HOST_NAME()), 'hello', 'hostname round-trips');
    is($p2->getOptionValue(DHO_DOMAIN_NAME()), 'example.com', 'domain round-trips');
    is($p2->getOptionRaw(DHO_DHCP_OPTION_OVERLOAD()), undef, 'no option 52 in round-trip');
    is($p2->getOptionValue(DHO_DHCP_MESSAGE_TYPE()), DHCPACK(), 'msg type round-trips');
};

subtest 'overloaded field with interleaved PAD bytes' => sub {
    plan tests => 2;
    my $sname_body = pack('C', DHO_PAD())  # PAD
                   . pack('C', DHO_HOST_NAME())
                   . pack('C', 5) . 'hello'
                   . pack('C', DHO_PAD())  # PAD
                   . pack('C', DHO_END());
    my $sname = "\x00" . $sname_body;
    $sname .= "\x00" x (64 - length($sname)) if length($sname) < 64;
    my $file = "\x00" x 128;

    my $opt_area = MAGIC_COOKIE()
                 . pack('C', DHO_DHCP_OPTION_OVERLOAD())
                 . pack('C', 1)
                 . pack('C', 3)
                 . pack('C', DHO_END());

    my $pkt = pack('C C C C N n n a4 a4 a4 a4 a16',
        BOOTREPLY(), HTYPE_ETHER(), ETHERNET_MAC_LEN(), 0,
        0x12345678, 0, 0,
        NULL_IP, NULL_IP, NULL_IP, NULL_IP,
        "\x00" x 16
    ) . $sname . $file . $opt_area;
    $pkt .= "\x00" x (300 - length($pkt)) if length($pkt) < 300;

    my $p = Net::DHCP::Packet->new($pkt);
    is($p->getOptionValue(DHO_HOST_NAME()), 'hello', 'hostname extracted past PAD in sname');
    is($p->getOptionRaw(DHO_DHCP_OPTION_OVERLOAD()), undef, 'option 52 removed');
};

