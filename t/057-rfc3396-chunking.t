#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 8;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':dho_codes' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':vendor43_codes' ); }
BEGIN { use_ok( 'Net::DHCP::Constants', ':dhcp_other' ); }

# Helper: count option-43 instances in serialized bytes and return their data lengths
sub count_option_instances {
    my $bytes = shift;
    my $code  = shift;
    my $code_char = chr($code);
    my $pos = 0;
    my $total = length($bytes);
    my @lengths;
    while ($pos < $total) {
        my $byte = substr($bytes, $pos, 1);
        if ($byte eq $code_char) {
            $pos++;
            my $len = ord(substr($bytes, $pos, 1));
            $pos++;
            push @lengths, $len;
            $pos += $len;
        }
        else {
            $pos++;
        }
    }
    return @lengths;
}

subtest 'suboption chunking across multiple option instances' => sub {
    plan tests => 5;

    my $p = Net::DHCP::Packet->new(
        op      => 1,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => 0x1234,
        secs    => 0,
        flags   => 0,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '0.0.0.0',
        chaddr  => '000102030405',
        sname   => '',
        file    => '',
        isDhcp  => 1,
        padding => '',
    );

    # Add suboptions whose packed data exceeds MAX_OPTION_DATA_LEN (255).
    # Each VENDOR43_CM_PS_SYSTEM_DESC (code 12) is 30 bytes of string data.
    # Wire entry per suboption: 1 (subcode=12) + 1 (len=30) + 30 (data) = 32 bytes.
    # 8 entries = 256 bytes -> triggers a new chunk at the 8th.
    my $description = 'X' x 30;
    for my $i (1 .. 8) {
        $p->addSubOptionValue(
            DHO_VENDOR_ENCAPSULATED_OPTIONS(),
            VENDOR43_CM_PS_SYSTEM_DESC(),
            $description,
        );
    }

    # Also add a standalone byte suboption to test the second chunk
    $p->addSubOptionValue(
        DHO_VENDOR_ENCAPSULATED_OPTIONS(),
        VENDOR43_DEVICE_TYPE(),
        '1',
    );

    my $serialized = $p->serialize();

    my @lengths = count_option_instances($serialized, DHO_VENDOR_ENCAPSULATED_OPTIONS());
    is(scalar @lengths, 2, 'serialized into two option-43 instances');

    # First chunk: 8 entries × 32 bytes = 256 -> should split, giving 7 entries = 224
    is($lengths[0], 7 * 32, 'first chunk has 7 suboptions (224 bytes)');
    # Second chunk: 1 string entry (32) + 1 byte entry: subcode(1) + len(1) + data(1) = 3
    is($lengths[1], 32 + 3, 'second chunk has 1 string + 1 byte suboption (35 bytes)');

    # Each chunk must not exceed MAX_OPTION_DATA_LEN
    for my $len (@lengths) {
        ok($len <= MAX_OPTION_DATA_LEN, "chunk length $len <= MAX_OPTION_DATA_LEN");
    }
};

subtest 'single suboption below threshold does not chunk' => sub {
    plan tests => 2;

    my $p = Net::DHCP::Packet->new(
        op      => 1,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => 0x1234,
        secs    => 0,
        flags   => 0,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '0.0.0.0',
        chaddr  => '000102030405',
        sname   => '',
        file    => '',
        isDhcp  => 1,
        padding => '',
    );

    $p->addSubOptionValue(
        DHO_VENDOR_ENCAPSULATED_OPTIONS(),
        VENDOR43_DEVICE_TYPE(),
        '1',
    );

    my $serialized = $p->serialize();
    my @lengths = count_option_instances($serialized, DHO_VENDOR_ENCAPSULATED_OPTIONS());
    is(scalar @lengths, 1, 'small suboptions produce single instance');
    is($lengths[0], 3, 'single byte suboption is 3 bytes on wire');
};

subtest 'round-trip: chunked suboptions are concatenated on parse' => sub {
    plan tests => 6;

    my $p = Net::DHCP::Packet->new(
        op      => 1,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => 0x1234,
        secs    => 0,
        flags   => 0,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '0.0.0.0',
        chaddr  => '000102030405',
        sname   => '',
        file    => '',
        isDhcp  => 1,
        padding => '',
    );

    # Build suboptions that chunk across multiple option-43 instances
    my $description = 'X' x 30;
    for my $i (1 .. 8) {
        $p->addSubOptionValue(
            DHO_VENDOR_ENCAPSULATED_OPTIONS(),
            VENDOR43_CM_PS_SYSTEM_DESC(),
            $description,
        );
    }
    $p->addSubOptionValue(
        DHO_VENDOR_ENCAPSULATED_OPTIONS(),
        VENDOR43_DEVICE_TYPE(),
        '1',
    );

    my $serialized = $p->serialize();

    # Verify serialization produces two option-43 instances
    my @lengths = count_option_instances($serialized, DHO_VENDOR_ENCAPSULATED_OPTIONS());
    is(scalar @lengths, 2, 'serialization produces two option-43 instances');

    # Round-trip: parse the serialized bytes
    my $p2 = Net::DHCP::Packet->new($serialized);

    # After parse, option 43 should have all suboptions (concatenated raw)
    ok(defined $p2->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS()),
       'option 43 is present after round-trip');

    my $total_raw_len = length($p2->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS()));
    my $expected_len = 8 * (1 + 1 + 30) + (1 + 1 + 1);
    is($total_raw_len, $expected_len,
       "raw option 43 data is fully concatenated ($expected_len bytes)");

    # Re-serialize and verify again — should still produce two instances
    my $reserialized = $p2->serialize();
    my @lengths2 = count_option_instances($reserialized, DHO_VENDOR_ENCAPSULATED_OPTIONS());
    is(scalar @lengths2, 2, 're-serialization still produces two option-43 instances');

    # Each re-serialized chunk still under MAX_OPTION_DATA_LEN
    for my $len (@lengths2) {
        ok($len <= MAX_OPTION_DATA_LEN, "re-serialized chunk length $len <= MAX_OPTION_DATA_LEN");
    }
};

subtest 'round-trip: long scalar option data is chunked and re-concatenated' => sub {
    plan tests => 4;

    # Build a raw option with >255 bytes of data
    my $long_data = 'A' x 300;

    my $p = Net::DHCP::Packet->new(
        op      => 1,
        htype   => 1,
        hlen    => 6,
        hops    => 0,
        xid     => 0x1234,
        secs    => 0,
        flags   => 0,
        ciaddr  => '0.0.0.0',
        yiaddr  => '0.0.0.0',
        siaddr  => '0.0.0.0',
        giaddr  => '0.0.0.0',
        chaddr  => '000102030405',
        sname   => '',
        file    => '',
        isDhcp  => 1,
        padding => '',
    );
    $p->addOptionRaw(43, $long_data);

    my $serialized = $p->serialize();

    # Verify serialization chunks into two option-43 instances
    my @lengths = count_option_instances($serialized, DHO_VENDOR_ENCAPSULATED_OPTIONS());
    is(scalar @lengths, 2, 'long scalar option is serialized as two instances');
    is($lengths[0], 255, 'first chunk is 255 bytes');
    is($lengths[1], 45, 'second chunk is remaining 45 bytes');

    # Round-trip: parse back and verify data is reconstructed
    my $p2 = Net::DHCP::Packet->new($serialized);
    my $recovered = $p2->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS());
    is(length($recovered), 300, 'concatenated data is full 300 bytes after round-trip');
};
