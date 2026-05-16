#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;

sub pack_subopt {
    my ($type, $val) = @_;
    return pack("C C a*", $type, length($val), $val);
}

BEGIN { use_ok( 'Net::DHCP::Packet' ); }

subtest 'quoting triggers (space, comma, double-quote)' => sub {
plan tests => 3;
my $p;

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, 'hello world'));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "hello world"', 'space triggers quoting');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, 'a,b'));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "a,b"', 'comma triggers quoting');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, q{a"b}));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "a\"b"', 'double quote escaped inside quoted value');
};

subtest 'backslash handling' => sub {
plan tests => 4;
my $p;

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, q{a\b}));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => a\b', 'backslash preserved when no quoting needed');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, q{a\\b}));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => a\\b', 'multiple backslashes preserved when no quoting');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, q{a\"b}));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "a\\\\\\"b"', 'backslash before quote — both escaped');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, 'a\\'));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => a\\', 'trailing backslash preserved');
};

subtest 'non-printable bytes' => sub {
plan tests => 4;
my $p;

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, "a\x00b"));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => a\x00b', 'non-printable byte shown as \xNN');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, "a\x00 b"));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "a\x00 b"', 'non-printable \xNN not double-escaped inside quotes');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, "\x01\x02\x03"));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => \x01\x02\x03', 'multiple non-printable bytes');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, "\x00,\x01"));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "\x00,\x01"', 'non-printable bytes with comma trigger quoting');
};

subtest 'edge cases' => sub {
plan tests => 3;
my $p;

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, ''));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => ', 'empty value');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(255, 'foo'));
is($p->getOptionValue(82), '255 => foo', 'unknown subcode shows numeric code');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, q{"}));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "\""', 'single double-quote value');
};

subtest 'mixed/advanced escaping' => sub {
plan tests => 3;
my $p;

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, 'hello'));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => hello', 'simple printable value');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82, pack_subopt(1, q{a\b "c"}));
is($p->getOptionValue(82), 'RAI_CIRCUIT_ID => "a\\\\b \"c\""', 'backslash and double quote both escaped inside quotes');

$p = Net::DHCP::Packet->new();
$p->addOptionRaw(82,
    pack_subopt(1, 'hello')
  . pack_subopt(2, 'foo bar')
  . pack_subopt(3, 'a,b')
);
is($p->getOptionValue(82),
    'RAI_CIRCUIT_ID => hello, RAI_REMOTE_ID => "foo bar", RAI_AGENT_ID => "a,b"',
    'multiple suboptions with mixed quoting');
};
