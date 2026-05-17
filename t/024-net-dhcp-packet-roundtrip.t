#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 17;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants' ); }
BEGIN { use_ok( 'Net::DHCP::Packet::IPv4Utils', ':all' ); }

sub pcid { Net::DHCP::Packet::packclientid(@_) }
sub ucid { Net::DHCP::Packet::unpackclientid(@_) }
sub psip { Net::DHCP::Packet::packsipserv(@_) }
sub usip { Net::DHCP::Packet::unpacksipserv(@_) }
sub pcsr { Net::DHCP::Packet::packcsr(@_) }
sub ucsr { Net::DHCP::Packet::unpackcsr(@_) }
sub psub { Net::DHCP::Packet::packsuboptions(@_) }
sub usub { Net::DHCP::Packet::unpacksuboptions(@_) }
sub puc  { Net::DHCP::Packet::packuserclass(@_) }
sub uuc  { Net::DHCP::Packet::unpackuserclass(@_) }

# ----- packclientid / unpackclientid -----

subtest 'packclientid / unpackclientid' => sub {
    plan tests => 26;

    # --- packclientid: type 1 (hex MAC) ---
    my $bin = pcid('0010A706DFFF');
    is(unpack('C', substr($bin, 0, 1)), 1,       'type byte = 1 for hex');
    is(unpack('H*', substr($bin, 1)), '0010a706dfff', 'value packed as raw bytes');

    # lowercase hex
    $bin = pcid('aabbccddee01');
    is(unpack('C', substr($bin, 0, 1)), 1,       'type byte = 1 for lowercase hex');
    is(unpack('H*', substr($bin, 1)), 'aabbccddee01', 'lowercase hex preserved');

    # --- packclientid: type 0 (text) ---
    $bin = pcid('my-client-id');
    is(unpack('C', substr($bin, 0, 1)), 0,       'type byte = 0 for text');
    is(substr($bin, 1), 'my-client-id',          'text value appended verbatim');

    $bin = pcid('text with spaces');
    is(unpack('C', substr($bin, 0, 1)), 0,       'type 0 for text with spaces');
    is(substr($bin, 1), 'text with spaces',      'spaces preserved in text');

    # odd-length hex is NOT hex → treated as type 0 (it's an even-length requirement)
    $bin = pcid('ABC');
    is(unpack('C', substr($bin, 0, 1)), 0,       'odd-length hex → type 0');

    # "0" corner case: valid FQDN, not falsy
    $bin = pcid('0');
    is(unpack('C', substr($bin, 0, 1)), 0,       'type byte = 0 for "0" string');
    is(substr($bin, 1), '0',                      '"0" value preserved');

    # undef / empty
    is(pcid(undef), undef,                        'packclientid undef returns undef');
    is(pcid(''),    undef,                        'packclientid empty returns undef');

    # --- unpackclientid: type 1 ---
    $bin = pack('C', 1) . pack('H*', '00deadd0beef');
    is(ucid($bin), '00deadd0beef',                'unpackclientid type 1 decodes hex');

    # --- unpackclientid: type 0 ---
    $bin = pack('C', 0) . 'hello';
    is(ucid($bin), 'hello',                       'unpackclientid type 0 decodes text');

    $bin = pack('C', 0) . '0';
    is(ucid($bin), '0',                           'unpackclientid type 0 decodes "0"');

    # --- unpackclientid: other types (pass-through) ---
    $bin = pack('C', 42) . 'raw data';
    is(ucid($bin), $bin,                          'unpackclientid other types passthrough');

    # --- unpackclientid: undef / empty ---
    is(ucid(undef), undef,                        'unpackclientid undef returns undef');
    is(ucid(''),    undef,                        'unpackclientid empty returns undef');

    # --- round-trip pack → unpack ---
    is(ucid(pcid('0010A706DFFF')),   '0010a706dfff', 'round-trip: hex');
    is(ucid(pcid('aabbccdd')),       'aabbccdd',      'round-trip: hex lowercase');
    is(ucid(pcid('client-42')),      'client-42',     'round-trip: text');
    is(ucid(pcid('x')),              'x',              'round-trip: single char');
    is(ucid(pcid('0')),              '0',              'round-trip: "0" string');

    # --- round-trip unpack → pack (back to same wire format) ---
    # Only types 0 and 1 are reconstructable; exotic types lose type info on unpack
    for my $wire (
        pack('C', 1) . pack('H*', 'deadbeef'),
        pack('C', 0) . 'some-id',
    ) {
        my $unpacked = ucid($wire);
        is(pcid($unpacked), $wire,       "unpack-then-pack preserves wire for type ".unpack('C', $wire));
    }
};

# ----- packsipserv / unpacksipserv -----

subtest 'packsipserv / unpacksipserv' => sub {
    plan tests => 23;

    # --- packsipserv: type 1 (IP) ---
    my $bin = psip('10.0.0.1');
    is(unpack('C', substr($bin, 0, 1)), 1,          'type byte = 1 for IP');
    is(unpackinet(substr($bin, 1)), '10.0.0.1',     'single IP packed correctly');

    $bin = psip('10.0.0.1 192.168.1.1');
    is(unpack('C', substr($bin, 0, 1)), 1,          'type byte = 1 for multiple IPs');
    is(unpackinets(substr($bin, 1)), '10.0.0.1 192.168.1.1', 'multiple IPs packed');

    # --- packsipserv: type 0 (domain) ---
    $bin = psip('sip.example.com');
    is(unpack('C', substr($bin, 0, 1)), 0,          'type byte = 0 for domain');
    is(substr($bin, 1), 'sip.example.com',          'domain appended verbatim');

    # --- packsipserv: detection edge cases ---
    # "10.0.0" is not a valid IP (3 octets) → type 0
    $bin = psip('10.0.0');
    isnt(unpack('C', substr($bin, 0, 1)), 1,          'malformed IP "10.0.0" is not type 1');

    # "0" is not IP-ish (no dots) → type 0
    $bin = psip('0');
    is(unpack('C', substr($bin, 0, 1)), 0,          'type byte = 0 for "0"');
    is(substr($bin, 1), '0',                        '"0" value preserved');

    # undef / empty
    is(psip(undef), undef,                           'packsipserv undef returns undef');
    is(psip(''),    undef,                           'packsipserv empty returns undef');

    # --- unpacksipserv: type 1 ---
    $bin = pack('C', 1) . packinet('10.0.0.1');
    is(usip($bin), '10.0.0.1',                      'unpacksipserv type 1 decodes single IP');

    # --- unpacksipserv: type 0 ---
    $bin = pack('C', 0) . 'sip.example.com';
    is(usip($bin), 'sip.example.com',                'unpacksipserv type 0 decodes domain');

    $bin = pack('C', 0) . '0';
    is(usip($bin), '0',                              'unpacksipserv type 0 decodes "0"');

    # --- unpacksipserv: other types (pass-through) ---
    $bin = pack('C', 2) . "\x01\x02";
    is(usip($bin), $bin,                             'unpacksipserv other types passthrough');

    # --- unpacksipserv: undef / empty ---
    is(usip(undef), undef,                           'unpacksipserv undef returns undef');
    is(usip(''),    undef,                           'unpacksipserv empty returns undef');

    # --- round-trip pack → unpack ---
    is(usip(psip('10.0.0.1')),            '10.0.0.1',            'round-trip: single IP');
    is(usip(psip('10.0.0.1 192.168.1.1')), '10.0.0.1 192.168.1.1', 'round-trip: multiple IPs');
    is(usip(psip('sip.example.com')),     'sip.example.com',     'round-trip: domain');
    is(usip(psip('0')),                   '0',                   'round-trip: "0" string');

    # --- round-trip unpack → pack ---
    # Only types 0 and 1 are reconstructable; exotic types lose type info on unpack
    for my $wire (
        pack('C', 1) . packinet('1.2.3.4'),
        pack('C', 0) . 'sip.foo',
    ) {
        my $unpacked = usip($wire);
        is(psip($unpacked), $wire,        "unpack-then-pack preserves wire for type ".unpack('C', $wire));
    }
};

# ----- packcsr / unpackcsr -----

subtest 'packcsr / unpackcsr' => sub {
    plan tests => 34;

    # --- packcsr basics ---
    my $routes = [
        ['10.0.0.0/8',  '10.0.0.1'],
        ['192.168.0.0/16', '192.168.0.1'],
        ['0.0.0.0/0',   '10.0.0.1'],
    ];
    my $packed = pcsr($routes);
    ok(defined $packed && ref $packed eq 'ARRAY',  'returns arrayref');
    ok(length($packed->[0]) > 0,                   'produces binary');

    # --- unpackcsr basics ---
    my @unpacked = ucsr($packed->[0]);
    is(scalar @unpacked, 6,                        '3 routes = 6 list elements');
    is($unpacked[0], '10.0.0.0/8',                 '1st prefix');
    is($unpacked[1], '10.0.0.1',                   '1st gateway');
    is($unpacked[2], '192.168.0.0/16',             '2nd prefix');
    is($unpacked[3], '192.168.0.1',                '2nd gateway');
    is($unpacked[4], '0.0.0.0/0',                  'default route prefix');
    is($unpacked[5], '10.0.0.1',                   'default route gateway');

    # --- mask boundary cases ---
    my @masks = (
        [1,  '128.0.0.0/1',   '1.2.3.4'],
        [8,  '10.0.0.0/8',    '1.2.3.4'],
        [9,  '128.0.0.0/9',   '1.2.3.4'],
        [16, '192.168.0.0/16','1.2.3.4'],
        [17, '128.0.0.0/17',  '1.2.3.4'],
        [24, '10.0.0.0/24',   '1.2.3.4'],
        [25, '10.0.0.0/25',   '1.2.3.4'],
        [32, '10.0.0.1/32',   '1.2.3.4'],
    );
    for my $m (@masks) {
        my ($mask, $expected_prefix, $gw) = @$m;
        my $r = [[ "$expected_prefix", $gw ]];
        my $p = pcsr($r);
        my @u = ucsr($p->[0]);
        is($u[0], $expected_prefix, "mask $mask prefix round-trips");
        is($u[1], $gw,             "mask $mask gateway round-trips");
    }

    # --- single route ---
    $packed = pcsr([['172.16.0.0/12', '172.16.0.1']]);
    @unpacked = ucsr($packed->[0]);
    is($unpacked[0], '172.16.0.0/12', 'single route prefix');
    is($unpacked[1], '172.16.0.1',    'single route gateway');

    # --- undef / empty ---
    is(ucsr(undef), undef,                            'unpackcsr undef returns undef');
    is(ucsr(''),    undef,                            'unpackcsr empty returns undef');

    # --- full round-trip ---
    $routes = [
        ['10.0.0.0/8',    '10.0.0.1'],
        ['172.16.0.0/12', '172.16.0.1'],
        ['192.168.0.0/16','192.168.0.1'],
        ['0.0.0.0/0',     '10.0.0.1'],
    ];
    $packed = pcsr($routes);
    @unpacked = ucsr($packed->[0]);
    is(scalar @unpacked, 8, 'full round-trip: 8 elements (4 pairs)');
    is($unpacked[0], '10.0.0.0/8',    'full round-trip prefix 1');
    is($unpacked[2], '172.16.0.0/12', 'full round-trip prefix 2');
    is($unpacked[4], '192.168.0.0/16','full round-trip prefix 3');
    is($unpacked[6], '0.0.0.0/0',     'full round-trip prefix 4');
};

# ----- end-to-end through addOptionValue / getOptionValue -----

subtest 'integration via addOptionValue / getOptionValue' => sub {
    plan tests => 6;

    my $p = Net::DHCP::Packet->new;

    # add a client-id option via high-level API
    $p->addOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), '0010A706DFFF');
    my $raw = $p->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER());
    ok(defined $raw, 'client-id option stored');
    is(unpack('C', substr($raw, 0, 1)), 1, 'type byte = 1 via addOptionValue');
    is(unpack('H*', substr($raw, 1)), '0010a706dfff', 'value via addOptionValue');

    $p->addOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), 'my-id');
    $raw = $p->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER());
    is(unpack('C', substr($raw, 0, 1)), 0, 'type byte = 0 for text');
    is(substr($raw, 1), 'my-id', 'text value via addOptionValue');

    # SIP server
    $p->addOptionValue(DHO_SIP_SERVERS(), '10.0.0.1');
    $raw = $p->getOptionRaw(DHO_SIP_SERVERS());
    is(unpack('C', substr($raw, 0, 1)), 1, 'sipserv type byte = 1 via addOptionValue');
};

# ----- edge cases -----

subtest 'minimal clientid hex' => sub {
    plan tests => 2;

    my $bin = pcid('AA');
    is(unpack('C', substr($bin, 0, 1)), 1,   '1-byte hex → type 1');
    is(unpack('H*', substr($bin, 1)), 'aa',  '1-byte hex value correct');
};

subtest 'packcsr edge cases' => sub {
    plan tests => 5;

    # empty routes
    my $result = pcsr([]);
    is(ref $result, 'ARRAY',          'empty routes returns arrayref');
    is(scalar @$result, 1,            'single chunk');
    is($result->[0], '',              'chunk is empty string');

    # multi-chunk: enough /32 routes to exceed 255-byte limit
    # each route: 1 (mask) + 4 (addr) + 4 (router) = 9 bytes
    # chunk threshold: length > 255 - 8 = 247 → ~27 routes per chunk
    my @routes;
    for my $i (1..30) {
        push @routes, ["10.0.0.$i/32", '10.0.0.1'];
    }
    $result = pcsr(\@routes);
    ok(scalar @$result > 1,            '30 routes split into multiple chunks');
    ok(length($result->[1]) > 0,       'second chunk populated');
};

subtest 'serialized round-trip' => sub {
    plan tests => 8;

    my $p = Net::DHCP::Packet->new;
    $p->addOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), '0010A706DFFF');
    $p->addOptionValue(DHO_SIP_SERVERS(), '10.0.0.1');
    $p->addOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), '10.0.0.0/8 10.0.0.1 192.168.0.0/16 192.168.0.1');

    my $wire = $p->serialize;
    ok(length($wire) > 0, 'serialized packet non-empty');

    my $p2 = Net::DHCP::Packet->new($wire);
    ok(defined $p2, 'deserialized packet created');

    my $cid_raw = $p2->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER());
    ok(defined $cid_raw, 'client-id survived serialized round-trip');
    is(unpack('C', substr($cid_raw, 0, 1)), 1, 'client-id type byte preserved');
    is(unpack('H*', substr($cid_raw, 1)), '0010a706dfff', 'client-id value preserved');

    my $sip_raw = $p2->getOptionRaw(DHO_SIP_SERVERS());
    ok(defined $sip_raw, 'sipserv survived serialized round-trip');

    my $csr_val = $p2->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
    like($csr_val, qr/10\.0\.0\.0\/8/,  'CSR prefix 1 round-trip');
    like($csr_val, qr/192\.168\.0\.0\/16/, 'CSR prefix 2 round-trip');
};

subtest 'getOptionValue decode' => sub {
    plan tests => 3;

    my $p = Net::DHCP::Packet->new;
    $p->addOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), 'aabbccdd');
    my $val = $p->getOptionValue(DHO_DHCP_CLIENT_IDENTIFIER());
    like($val, qr/aabbccdd/, 'clientid decoded through getOptionValue');

    $p->addOptionValue(DHO_SIP_SERVERS(), '10.0.0.1');
    $val = $p->getOptionValue(DHO_SIP_SERVERS());
    like($val, qr/10\.0\.0\.1/, 'sipserv decoded through getOptionValue');

    # CSR via addOptionValue (packcsr handles both arrayref and scalar string)
    $p->addOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), '10.0.0.0/8 10.0.0.1');
    $val = $p->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
    like($val, qr/10\.0\.0\.0\/8/, 'CSR via addOptionValue');
};

# ----- regression: unpacksipserv type-0 fix -----

subtest 'unpacksipserv type-0 fix' => sub {
    plan tests => 2;

    # wire: type 0 + "sip.domain.com"
    my $wire = pack('C', 0) . 'sip.domain.com';
    is(usip($wire), 'sip.domain.com', 'type 0 returns domain string');

    # round-trip through pack → unpack
    is(usip(psip('sip.domain.com')), 'sip.domain.com', 'type 0 round-trip: domain.com');
};

# ----- CSR default route (mask=0, zero address bytes) -----

subtest 'CSR default route' => sub {
    plan tests => 2;

    # manually build wire: mask=0, no addr bytes, router 10.0.0.1
    my $wire = pack('C', 0) . packinet('10.0.0.1');
    my @r = ucsr($wire);
    is($r[0], '0.0.0.0/0', 'default route prefix');
    is($r[1], '10.0.0.1',  'default route gateway');
};

# ----- packsuboptions / unpacksuboptions -----

subtest 'packsuboptions / unpacksuboptions' => sub {
    plan tests => 12;

    # basic round-trip
    my @opts = (
        [1, "\x00\x04\x00\x01\x00\x02"],
        [2, "\x00\x06\xaa\xbb\xcc\xdd\xee\xff"],
    );
    my $packed = psub(@opts);
    ok(defined $packed,                         'packsuboptions returns defined');
    ok(length $packed > 0,                      'packsuboptions returns non-empty');

    my @unpacked = usub($packed);
    is(scalar @unpacked, 2,                     'unpacksuboptions returns 2 suboptions');
    is($unpacked[0][0], 1,                      'suboption 1 type preserved');
    is($unpacked[0][1], $opts[0][1],            'suboption 1 data preserved');
    is($unpacked[1][0], 2,                      'suboption 2 type preserved');
    is($unpacked[1][1], $opts[1][1],            'suboption 2 data preserved');

    # wire format: type | len | data | type | len | data (no outer length prefix)
    is(length $packed, (1+1+6) + (1+1+8),       'wire format = all entries, no outer len');
    my $pos = 0;
    is(ord(substr($packed, $pos++, 1)), 1,      'type byte 1');
    my $len = ord(substr($packed, $pos++, 1));
    is($len, length($opts[0][1]),                 'length byte 1 = 6 (not 7, no double-packing)');

    # undef / empty
    is(usub(undef), undef,                      'unpacksuboptions undef returns undef');
    is(usub(''),    undef,                      'unpacksuboptions empty returns undef');
};

# ----- multi-chunk CSR round-trip (>255 bytes) -----

subtest 'multi-chunk CSR round-trip' => sub {
    plan tests => 32;

    my @routes;
    for my $i (1..30) {
        push @routes, ["10.0.0.$i/32", '10.0.0.1'];
    }

    my $p = Net::DHCP::Packet->new;
    $p->addOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), \@routes);

    my $wire = $p->serialize;
    ok(length($wire) > 0, '30-route CSR serialized');

    my $p2 = Net::DHCP::Packet->new($wire);
    ok(defined $p2, '30-route CSR deserialized');

    my $csr_val = $p2->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
    for my $i (1..30) {
        like($csr_val, qr/10\.0\.0\.$i\/32/, "route $i survived round-trip");
    }
};

# ----- packuserclass / unpackuserclass -----

subtest 'packuserclass / unpackuserclass' => sub {
    plan tests => 20;

    # --- packuserclass: single value ---
    my $bin = puc('ipxe');
    is(length $bin, 5,                           'single userclass: 1 + 4 bytes');
    is(ord(substr $bin, 0, 1), 4,                'length byte = 4');
    is(substr($bin, 1), 'ipxe',                  'data = "ipxe"');

    # --- packuserclass: multiple values ---
    $bin = puc('ipxe', 'BIOS');
    is(length $bin, 10,                          'two userclasses: 2 * (1 + 4)');
    my $pos = 0;
    is(ord(substr $bin, $pos, 1), 4,             'first block length = 4');
    $pos++;
    is(substr($bin, $pos, 4), 'ipxe',            'first block data = "ipxe"');
    $pos += 4;
    is(ord(substr $bin, $pos, 1), 4,             'second block length = 4');
    $pos++;
    is(substr($bin, $pos, 4), 'BIOS',            'second block data = "BIOS"');

    # --- packuserclass: value with spaces (preserved as one block) ---
    $bin = puc('foo bar');
    is(length $bin, 8,                           'spaced value: 1 + 7 bytes');
    is(ord(substr $bin, 0, 1), 7,                'length byte = 7');
    is(substr($bin, 1), 'foo bar',               'data = "foo bar" (preserved)');

    # --- packuserclass: undef and empty skipped ---
    $bin = puc('a', undef, '', 'b');
    is(length $bin, 4,                           'two of four non-empty');
    is(ord(substr $bin, 0, 1), 1,                'first block length = 1');
    is(substr($bin, 1, 1), 'a',                  'first block data = "a"');
    is(ord(substr $bin, 2, 1), 1,                'second block length = 1');
    is(substr($bin, 3, 1), 'b',                  'second block data = "b"');

    # --- unpackuserclass: single block ---
    $bin = pack('C/a*', 'ipxe');
    is(uuc($bin), 'ipxe',                        'single block decoded');

    # --- unpackuserclass: multiple blocks ---
    $bin = pack('C/a*', 'ipxe') . pack('C/a*', 'BIOS');
    is(uuc($bin), 'ipxe, BIOS',                  'two blocks joined with comma');

    # --- unpackuserclass: undef / empty ---
    is(uuc(undef), undef,                        'unpackuserclass undef returns undef');
    is(uuc(''),    undef,                        'unpackuserclass empty returns undef');
};

# ----- userclass addOptionValue multi-class round-trip -----

subtest 'userclass addOptionValue multi-class round-trip' => sub {
    plan tests => 3;

    my $p = Net::DHCP::Packet->new;
    $p->addOptionValue(DHO_USER_CLASS(), 'ipxe, BIOS');

    my $wire = $p->serialize;
    my $p2   = Net::DHCP::Packet->new($wire);

    ok(defined $p2, 'deserialized userclass packet');

    my $val = $p2->getOptionValue(DHO_USER_CLASS());
    is($val, 'ipxe, BIOS', 'round-trip: split -> pack -> serialize -> parse -> join');

    # Also verify via raw: two RFC 3004 blocks
    my $raw = $p2->getOptionRaw(DHO_USER_CLASS());
    is(length($raw), 10, 'two userclass blocks on wire: 2 * (1 + 4) bytes');
};
