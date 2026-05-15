#!/usr/bin/env perl

use Test::More tests => 9;
use Test::Warn;

BEGIN { use_ok( 'Net::DHCP::Packet' ); }

use strict;
use warnings;

my $pac = Net::DHCP::Packet->new();
my $ref_packet = pack( 'H*',
        '0101060011223344000080000a0000010a0000020a0000030a00000400112233'
      . '445566778899aabbccddeeff3132333435363738393031323334353637383930'
      . '3132333435363738393031323334353637383930313233343536373839303132'
      . '3334353637383930313233003132333435363738393031323334353637383930'
      . '3132333435363738393031323334353637383930313233343536373839303132'
      . '3334353637383930313233343536373839303132333435363738393031323334' );

is( $pac->min_len_handling, 0, 'default' );

$pac->min_len_handling(1);

warnings_like {
    ok( eval { $pac->marshall($ref_packet); 1 }, 'no exceptions' );
} [
    qr/, absolute minimum size/,
    qr/, minimum size/],
'warning';

is( $pac->min_len_handling, 1, 'warn' );

$pac->min_len_handling(2);

warning_is {
    ok( eval { $pac->marshall($ref_packet); 1 }, 'no exceptions' );
} undef, 'ignore';

is( $pac->min_len_handling, 2, 'ignore' );

ok( ! eval { $pac->min_len_handling(3); 1 }, 'invalid level' );
