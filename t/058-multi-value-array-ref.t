#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 11;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants' ); }

subtest 'default legacy mode returns comma-joined strings' => sub {
    plan tests => 3;

    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_ROUTERS(), '192.0.2.1, 192.0.2.2');
    $p->setOptionValue(DHO_USER_CLASS(), 'ipxe, BIOS');

    my $routers = $p->getOptionValue(DHO_ROUTERS());
    is(ref $routers, '', 'routers is a plain string');
    is($routers, '192.0.2.1, 192.0.2.2', 'routers joined with comma');

    my $uc = $p->getOptionValue(DHO_USER_CLASS());
    is($uc, 'ipxe, BIOS', 'userclass joined with comma');
};

subtest 'global multi_value_array_ref returns arrayrefs' => sub {
    plan tests => 4;

    local $Net::DHCP::multi_value_array_ref = 1;
    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_ROUTERS(), '192.0.2.1, 192.0.2.2');
    $p->setOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST(), '1, 2, 3');

    my $routers = $p->getOptionValue(DHO_ROUTERS());
    is(ref $routers, 'ARRAY', 'routers is an arrayref');
    is_deeply($routers, ['192.0.2.1', '192.0.2.2'], 'routers decoded as two IPs');

    my $prl = $p->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST());
    is(ref $prl, 'ARRAY', 'PRL is an arrayref');
    is_deeply($prl, ['1', '2', '3'], 'PRL decoded as three bytes');
};

subtest 'constructor arg overrides global' => sub {
    plan tests => 2;

    local $Net::DHCP::multi_value_array_ref = 0;
    my $p = Net::DHCP::Packet->new(multi_value_array_ref => 1);
    $p->setOptionValue(DHO_ROUTERS(), '192.0.2.1, 192.0.2.2');

    my $routers = $p->getOptionValue(DHO_ROUTERS());
    is(ref $routers, 'ARRAY', 'constructor arg produces arrayref despite global=0');

    # Another object without the arg should use global
    my $p2 = Net::DHCP::Packet->new;
    $p2->setOptionValue(DHO_ROUTERS(), '192.0.2.1');
    my $r2 = $p2->getOptionValue(DHO_ROUTERS());
    is(ref $r2, '', 'second object without arg returns string');
};

subtest 'per-object method after construction' => sub {
    plan tests => 3;

    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_ROUTERS(), '192.0.2.1, 192.0.2.2');

    $p->multi_value_array_ref(1);
    my $routers = $p->getOptionValue(DHO_ROUTERS());
    is(ref $routers, 'ARRAY', 'method(1) enables arrayref');

    $p->multi_value_array_ref(0);
    my $r2 = $p->getOptionValue(DHO_ROUTERS());
    is(ref $r2, '', 'method(0) reverts to string');
    is($r2, '192.0.2.1, 192.0.2.2', 'string value preserved');
};

subtest 'method returns current value' => sub {
    plan tests => 2;

    my $p = Net::DHCP::Packet->new;
    is($p->multi_value_array_ref, 0, 'default is 0');
    $p->multi_value_array_ref(1);
    is($p->multi_value_array_ref, 1, 'returns 1 after set');
};

subtest 'userclass round-trip with arrayref' => sub {
    plan tests => 3;

    local $Net::DHCP::multi_value_array_ref = 1;
    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_USER_CLASS(), 'ipxe, BIOS');

    my $wire = $p->serialize;
    my $p2   = Net::DHCP::Packet->new($wire);

    my $uc = $p2->getOptionValue(DHO_USER_CLASS());
    is(ref $uc, 'ARRAY', 'userclass is arrayref');
    is_deeply($uc, ['ipxe', 'BIOS'], 'two userclass values');
    is(scalar @$uc, 2, 'exactly two entries');
};

subtest 'csr round-trip with arrayref' => sub {
    plan tests => 2;

    local $Net::DHCP::multi_value_array_ref = 1;
    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), "192.0.2.0/8 192.0.2.1, 198.51.100.0/16 198.51.100.1");

    my $routes = $p->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
    is(ref $routes, 'ARRAY', 'CSR is arrayref');
    like($routes->[0], qr/192\.0\.0\.0/, 'first route preserved');
};

subtest 'inets2 (pairs) with arrayref' => sub {
    plan tests => 2;

    local $Net::DHCP::multi_value_array_ref = 1;
    my $p = Net::DHCP::Packet->new;
    # DHO_STATIC_ROUTES is inets2 (pairs of IPs)
    $p->setOptionValue(DHO_STATIC_ROUTES(), '192.0.2.1 203.0.113.1, 192.0.2.2 203.0.113.2');

    my $routes = $p->getOptionValue(DHO_STATIC_ROUTES());
    is(ref $routes, 'ARRAY', 'inets2 is arrayref');
    like($routes->[0], qr/192\.0\.2\.1/, 'first pair preserved');
};

subtest 'arrayref mode does not affect input side' => sub {
    plan tests => 2;

    local $Net::DHCP::multi_value_array_ref = 1;
    my $p = Net::DHCP::Packet->new;
    # setOptionValue with string input still works the same
    $p->setOptionValue(DHO_ROUTERS(), '192.0.2.1, 192.0.2.2, 192.0.2.3');

    my $raw = $p->getOptionRaw(DHO_ROUTERS());
    # Should be 3 packed IPs = 12 bytes
    is(length $raw, 12, 'three IPs packed into 12 bytes');

    my $val = $p->getOptionValue(DHO_ROUTERS());
    is(scalar @$val, 3, 'three values in arrayref');
};
