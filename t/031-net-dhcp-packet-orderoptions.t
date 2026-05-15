#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 12;

BEGIN { use_ok( 'Net::DHCP::Packet::OrderOptions', qw( reorder_options ) ); }

# No quirks needed
is_deeply(
    [ reorder_options( 53, 60, 43, 82 ) ],
    [ 53, 60, 43, 82 ],
    'no reorder needed'
);

# 60 after 43 — swap
is_deeply(
    [ reorder_options( 53, 43, 60, 1 ) ],
    [ 53, 60, 43, 1 ],
    '60 moved before 43'
);

# 82 not at end — move to end
is_deeply(
    [ reorder_options( 82, 53, 54 ) ],
    [ 53, 54, 82 ],
    '82 moved to end'
);

# Both quirks: 60 after 43 + 82 not at end
is_deeply(
    [ reorder_options( 82, 43, 60 ) ],
    [ 60, 43, 82 ],
    'both quirks applied'
);

# Only 60, no 43
is_deeply(
    [ reorder_options( 53, 60 ) ],
    [ 53, 60 ],
    'only 60 present, no reorder'
);

# Only 43, no 60
is_deeply(
    [ reorder_options( 53, 43 ) ],
    [ 53, 43 ],
    'only 43 present, no reorder'
);

# Only 82
is_deeply(
    [ reorder_options( 82 ) ],
    [ 82 ],
    'only 82 present'
);

# No quirk-relevant codes
is_deeply(
    [ reorder_options( 1, 2, 3 ) ],
    [ 1, 2, 3 ],
    'no quirk codes present, unchanged'
);

# Empty list
is_deeply(
    [ reorder_options() ],
    [],
    'empty list'
);

# 60 and 43 adjacent, correct order
is_deeply(
    [ reorder_options( 60, 43, 82 ) ],
    [ 60, 43, 82 ],
    '60 already before 43, 82 at end'
);

# 60 and 43 equal position (same code shouldn't happen but be safe)
is_deeply(
    [ reorder_options( 60, 60, 43 ) ],
    [ 60, 60, 43 ],
    'duplicate 60 codes'
);
