#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 20;

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
    my $bin = psip('192.0.2.1');
    is(unpack('C', substr($bin, 0, 1)), 1,          'type byte = 1 for IP');
    is(unpackinet(substr($bin, 1)), '192.0.2.1',    'single IP packed correctly');

    $bin = psip('192.0.2.1 203.0.113.1');
    is(unpack('C', substr($bin, 0, 1)), 1,          'type byte = 1 for multiple IPs');
    is(unpackinets(substr($bin, 1)), '192.0.2.1 203.0.113.1', 'multiple IPs packed');

    # --- packsipserv: type 0 (domain) ---
    $bin = psip('sip.example.com');
    is(unpack('C', substr($bin, 0, 1)), 0,          'type byte = 0 for domain');
    is(substr($bin, 1), 'sip.example.com',          'domain appended verbatim');

    # --- packsipserv: detection edge cases ---
    # "192.0.2" is not a valid IP (3 octets) → type 0
    $bin = psip('192.0.2');
    isnt(unpack('C', substr($bin, 0, 1)), 1,          'malformed IP "192.0.2" is not type 1');

    # "0" is not IP-ish (no dots) → type 0
    $bin = psip('0');
    is(unpack('C', substr($bin, 0, 1)), 0,          'type byte = 0 for "0"');
    is(substr($bin, 1), '0',                        '"0" value preserved');

    # undef / empty
    is(psip(undef), undef,                           'packsipserv undef returns undef');
    is(psip(''),    undef,                           'packsipserv empty returns undef');

    # --- unpacksipserv: type 1 ---
    $bin = pack('C', 1) . packinet('192.0.2.1');
    is(usip($bin), '192.0.2.1',                     'unpacksipserv type 1 decodes single IP');

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
    is(usip(psip('192.0.2.1')),            '192.0.2.1',            'round-trip: single IP');
    is(usip(psip('192.0.2.1 203.0.113.1')), '192.0.2.1 203.0.113.1', 'round-trip: multiple IPs');
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

# ----- packclientid force_type override and NetAddr::MAC -----

subtest 'packclientid force type and NetAddr::MAC integration' => sub {
    plan tests => 6;

    my $bin = pcid('deadbeef', 'fqdn');
    is(unpack('C', substr($bin, 0, 1)), 0,       'force type = 0 for hex text');
    is(substr($bin, 1), 'deadbeef',                'forced payload preserved (no hex decode)');

    $bin = pcid('myhost', 'ether');
    is(unpack('C', substr($bin, 0, 1)), 1,        'force type = 1 for text');
    is(substr($bin, 1), 'myhost',                  'forced type 1 payload preserved');

    $bin = psip('192.0.2.1', 'domain');
    is(unpack('C', substr($bin, 0, 1)), 0,        'sipserv force type = 0 for IP');

    SKIP: {
        skip 'NetAddr::MAC not installed' unless eval { require NetAddr::MAC; 1 };
        my $mac = NetAddr::MAC->new('00:11:22:aa:bb:cc');
        my $packed = pack('C H*', 1, $mac->as_basic);
        is(unpack('H*', substr($packed, 1)), '001122aabbcc',
           'NetAddr::MAC round-trip');
    }
};

# ----- packcsr / unpackcsr -----

subtest 'packcsr / unpackcsr' => sub {
    plan tests => 34;

    # --- packcsr basics ---
    my $routes = [
        ['192.0.2.0/8',  '192.0.2.1'],
        ['198.51.100.0/16', '198.51.100.1'],
        ['0.0.0.0/0',   '192.0.2.1'],
    ];
    my $packed = pcsr($routes);
    ok(defined $packed && ref $packed eq 'ARRAY',  'returns arrayref');
    ok(length($packed->[0]) > 0,                   'produces binary');

    # --- unpackcsr basics ---
    my @unpacked = ucsr($packed->[0]);
    is(scalar @unpacked, 6,                        '3 routes = 6 list elements');
    is($unpacked[0], '192.0.0.0/8',                '1st prefix');
    is($unpacked[1], '192.0.2.1',                  '1st gateway');
    is($unpacked[2], '198.51.0.0/16',              '2nd prefix');
    is($unpacked[3], '198.51.100.1',               '2nd gateway');
    is($unpacked[4], '0.0.0.0/0',                  'default route prefix');
    is($unpacked[5], '192.0.2.1',                  'default route gateway');

    # --- mask boundary cases ---
    my @masks = (
        [1,  '128.0.0.0/1',    '1.2.3.4', '128.0.0.0/1'],
        [8,  '192.0.2.0/8',    '1.2.3.4', '192.0.0.0/8'],
        [9,  '128.0.0.0/9',    '1.2.3.4', '128.0.0.0/9'],
        [16, '198.51.100.0/16','1.2.3.4', '198.51.0.0/16'],
        [17, '128.0.0.0/17',   '1.2.3.4', '128.0.0.0/17'],
        [24, '192.0.2.0/24',   '1.2.3.4', '192.0.2.0/24'],
        [25, '192.0.2.0/25',   '1.2.3.4', '192.0.2.0/25'],
        [32, '192.0.2.1/32',   '1.2.3.4', '192.0.2.1/32'],
    );
    for my $m (@masks) {
        my ($mask, $input_prefix, $gw, $expected_prefix) = @$m;
        my $r = [[ "$input_prefix", $gw ]];
        my $p = pcsr($r);
        my @u = ucsr($p->[0]);
        is($u[0], $expected_prefix, "mask $mask prefix round-trips");
        is($u[1], $gw,             "mask $mask gateway round-trips");
    }

    # --- single route ---
    $packed = pcsr([['203.0.113.0/12', '203.0.113.1']]);
    @unpacked = ucsr($packed->[0]);
    is($unpacked[0], '203.0.0.0/12', 'single route prefix');
    is($unpacked[1], '203.0.113.1',  'single route gateway');

    # --- undef / empty ---
    is(ucsr(undef), undef,                            'unpackcsr undef returns undef');
    is(ucsr(''),    undef,                            'unpackcsr empty returns undef');

    # --- full round-trip ---
    $routes = [
        ['192.0.2.0/8',    '192.0.2.1'],
        ['203.0.113.0/12', '203.0.113.1'],
        ['198.51.100.0/16','198.51.100.1'],
        ['0.0.0.0/0',     '192.0.2.1'],
    ];
    $packed = pcsr($routes);
    @unpacked = ucsr($packed->[0]);
    is(scalar @unpacked, 8, 'full round-trip: 8 elements (4 pairs)');
    is($unpacked[0], '192.0.0.0/8',    'full round-trip prefix 1');
    is($unpacked[2], '203.0.0.0/12',   'full round-trip prefix 2');
    is($unpacked[4], '198.51.0.0/16',  'full round-trip prefix 3');
    is($unpacked[6], '0.0.0.0/0',      'full round-trip prefix 4');
};

# ----- end-to-end through setOptionValue / getOptionValue -----

subtest 'integration via setOptionValue / getOptionValue' => sub {
    plan tests => 6;

    my $p = Net::DHCP::Packet->new;

    # add a client-id option via high-level API
    $p->setOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), '0010A706DFFF');
    my $raw = $p->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER());
    ok(defined $raw, 'client-id option stored');
    is(unpack('C', substr($raw, 0, 1)), 1, 'type byte = 1 via setOptionValue');
    is(unpack('H*', substr($raw, 1)), '0010a706dfff', 'value via setOptionValue');

    $p->setOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), 'my-id');
    $raw = $p->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER());
    is(unpack('C', substr($raw, 0, 1)), 0, 'type byte = 0 for text');
    is(substr($raw, 1), 'my-id', 'text value via setOptionValue');

    # SIP server
    $p->setOptionValue(DHO_SIP_SERVERS(), '192.0.2.1');
    $raw = $p->getOptionRaw(DHO_SIP_SERVERS());
    is(unpack('C', substr($raw, 0, 1)), 1, 'sipserv type byte = 1 via setOptionValue');
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
        push @routes, ["192.0.2.$i/32", '192.0.2.1'];
    }
    $result = pcsr(\@routes);
    ok(scalar @$result > 1,            '30 routes split into multiple chunks');
    ok(length($result->[1]) > 0,       'second chunk populated');
};

subtest 'serialized round-trip' => sub {
    plan tests => 8;

    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), '0010A706DFFF');
    $p->setOptionValue(DHO_SIP_SERVERS(), '192.0.2.1');
    $p->setOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), '192.0.2.0/8 192.0.2.1 198.51.100.0/16 198.51.100.1');

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
    like($csr_val, qr/192\.0\.0\.0\/8/,  'CSR prefix 1 round-trip');
    like($csr_val, qr/198\.51\.0\.0\/16/, 'CSR prefix 2 round-trip');
};

subtest 'getOptionValue decode' => sub {
    plan tests => 3;

    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_DHCP_CLIENT_IDENTIFIER(), 'aabbccdd');
    my $val = $p->getOptionValue(DHO_DHCP_CLIENT_IDENTIFIER());
    is($val, 'aabbccdd', 'clientid decoded through getOptionValue');

    $p->setOptionValue(DHO_SIP_SERVERS(), '192.0.2.1');
    $val = $p->getOptionValue(DHO_SIP_SERVERS());
    is($val, '192.0.2.1', 'sipserv decoded through getOptionValue');

    # CSR via setOptionValue (packcsr handles both arrayref and scalar string)
    $p->setOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), '192.0.2.0/8 192.0.2.1');
    $val = $p->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
    like($val, qr/192\.0\.0\.0\/8/, 'CSR via setOptionValue');
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

    # manually build wire: mask=0, no addr bytes, router 192.0.2.1
    my $wire = pack('C', 0) . packinet('192.0.2.1');
    my @r = ucsr($wire);
    is($r[0], '0.0.0.0/0', 'default route prefix');
    is($r[1], '192.0.2.1',  'default route gateway');
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
        push @routes, ["192.0.2.$i/32", '192.0.2.1'];
    }

    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_CLASSLESS_STATIC_ROUTE(), \@routes);

    my $wire = $p->serialize;
    ok(length($wire) > 0, '30-route CSR serialized');

    my $p2 = Net::DHCP::Packet->new($wire);
    ok(defined $p2, '30-route CSR deserialized');

    my $csr_val = $p2->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
    for my $i (1..30) {
        like($csr_val, qr/192\.0\.2\.$i\/32/, "route $i survived round-trip");
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

# ----- userclass setOptionValue multi-class round-trip -----

subtest 'userclass setOptionValue multi-class round-trip' => sub {
    plan tests => 3;

    my $p = Net::DHCP::Packet->new;
    $p->setOptionValue(DHO_USER_CLASS(), 'ipxe, BIOS');

    my $wire = $p->serialize;
    my $p2   = Net::DHCP::Packet->new($wire);

    ok(defined $p2, 'deserialized userclass packet');

    my $val = $p2->getOptionValue(DHO_USER_CLASS());
    is($val, 'ipxe, BIOS', 'round-trip: split -> pack -> serialize -> parse -> join');

    # Also verify via raw: two RFC 3004 blocks
    my $raw = $p2->getOptionRaw(DHO_USER_CLASS());
    is(length($raw), 10, 'two userclass blocks on wire: 2 * (1 + 4) bytes');
};

# ----- pushOptionValue -----

subtest 'pushOptionValue' => sub {
    plan tests => 11;

    my $p = Net::DHCP::Packet->new;

    # pushOptionValue on inets (list format): first push stores scalar
    $p->pushOptionValue(DHO_ROUTERS(), '192.0.2.1');
    my $raw = $p->getOptionRaw(DHO_ROUTERS());
    ok(defined $raw, 'routers set after first push');
    is(length $raw, 4, 'one IP packed = 4 bytes');

    # second push promotes to arrayref
    $p->pushOptionValue(DHO_ROUTERS(), '192.0.2.2');
    my $stored = $p->{options}->{DHO_ROUTERS()};
    ok(ref $stored eq 'ARRAY', 'second push promotes to arrayref');
    is(scalar @$stored, 2, 'two chunks stored');

    # third push appends
    $p->pushOptionValue(DHO_ROUTERS(), '192.0.2.3');
    is(scalar @$stored, 3, 'third push appends to arrayref');

    # serialize, parse, verify all three IPs survived
    my $wire = $p->serialize;
    my $p2   = Net::DHCP::Packet->new($wire);
    my $val  = $p2->getOptionValue(DHO_ROUTERS());
    like($val, qr/192\.0\.2\.1/, 'first IP survived');
    like($val, qr/192\.0\.2\.2/, 'second IP survived');
    like($val, qr/192\.0\.2\.3/, 'third IP survived');

    # pushOptionValue on scalar-only format (inet) croaks
    eval {
        my $p3 = Net::DHCP::Packet->new;
        $p3->pushOptionValue(DHO_SUBNET_MASK(), '255.255.255.0');
    };
    like($@, qr/pushOptionValue.*does not accept multiple values/,
        'pushOptionValue on inet croaks');

    # pushOptionValue on csr
    {
        my $p4 = Net::DHCP::Packet->new;
        $p4->pushOptionValue(DHO_CLASSLESS_STATIC_ROUTE(),
            '192.0.2.0/8 192.0.2.1');
        $p4->pushOptionValue(DHO_CLASSLESS_STATIC_ROUTE(),
            '198.51.100.0/16 198.51.100.1');
        my $v = $p4->getOptionValue(DHO_CLASSLESS_STATIC_ROUTE());
        like($v, qr/192\.0\.0\.0/, 'CSR first push preserved');
        like($v, qr/198\.51\.0\.0/, 'CSR second push preserved');
    }
};

# ----- deprecated aliases -----

subtest 'deprecated aliases' => sub {
    plan tests => 6;

    my $p = Net::DHCP::Packet->new;

    # addOptionRaw deprecation warning
    {
        my @warnings;
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        $p->addOptionRaw(DHO_SUBNET_MASK(), "\xff\xff\xff\0");
        is(scalar @warnings, 1, 'addOptionRaw triggers one warning');
        like($warnings[0], qr/deprecated.*setOptionRaw/,
            'addOptionRaw warning mentions setOptionRaw');
        is($p->getOptionRaw(DHO_SUBNET_MASK()), "\xff\xff\xff\0",
            'addOptionRaw still sets value correctly');
    }

    # addOptionValue deprecation warning
    {
        my @warnings;
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        $p->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), DHCPINFORM());
        is(scalar @warnings, 1, 'addOptionValue triggers one warning');
        like($warnings[0], qr/deprecated.*setOptionValue/,
            'addOptionValue warning mentions setOptionValue');
        is($p->getOptionValue(DHO_DHCP_MESSAGE_TYPE()), DHCPINFORM(),
            'addOptionValue still sets value correctly');
    }
};
