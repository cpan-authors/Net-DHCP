#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 6;

BEGIN { use_ok( 'Net::DHCP::Packet::OrderOptions', qw( reorder_options ) ); }

subtest 'no quirks needed' => sub {
plan tests => 2;
is_deeply([ reorder_options( 53, 60, 43, 82 ) ], [ 53, 60, 43, 82 ], 'already in correct order');
is_deeply([ reorder_options( 1, 2, 3 ) ], [ 1, 2, 3 ], 'no quirk codes present');
};

subtest '60 after 43' => sub {
plan tests => 3;
is_deeply([ reorder_options( 53, 43, 60, 1 ) ], [ 53, 60, 43, 1 ], '60 moved before 43');
is_deeply([ reorder_options( 53, 60 ) ], [ 53, 60 ], 'only 60 present, no reorder');
is_deeply([ reorder_options( 53, 43 ) ], [ 53, 43 ], 'only 43 present, no reorder');
};

subtest '82 at end' => sub {
plan tests => 2;
is_deeply([ reorder_options( 82, 53, 54 ) ], [ 53, 54, 82 ], '82 moved to end');
is_deeply([ reorder_options( 82 ) ], [ 82 ], 'only 82 present');
};

subtest 'both quirks' => sub {
plan tests => 2;
is_deeply([ reorder_options( 82, 43, 60 ) ], [ 60, 43, 82 ], 'both quirks applied');
is_deeply([ reorder_options( 60, 43, 82 ) ], [ 60, 43, 82 ], '60 already before 43, 82 at end');
};

subtest 'edge cases' => sub {
plan tests => 2;
is_deeply([ reorder_options() ], [], 'empty list');
is_deeply([ reorder_options( 60, 60, 43 ) ], [ 60, 60, 43 ], 'duplicate 60 codes');
};
