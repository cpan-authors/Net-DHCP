#!/usr/bin/env perl
use strict;
use warnings;
use Test::More tests => 7;

BEGIN { use_ok('Net::DHCP::Constants'); }

use Net::DHCP::Constants
  qw(%DHO_CODES %DHCP_MESSAGE %NWIP_CODES %CCC_CODES %GEOCONF_CODES %RELAYAGENT_CODES);

# load in the iana definitions
my %iana;
eval {
    our $VAR1;
    for my $file (qw(  ./.iana.pl ../t/.iana.pl t/.iana.pl  )) {
        require $file if -f $file;
    }
    die "couldnt load iana file"
      unless ref $VAR1;
    %iana = %$VAR1;
};

SKIP: {
    skip( q|Couldn't load iana details, skipping coverage|, 6 ) if $@;

    subtest 'DHO_CODES — bootp-dhcp-parameters-1' => sub {
        plan 'no_plan';
        my @val = values %DHO_CODES;
        my $codes = $iana{registry}->{'bootp-dhcp-parameters-1'}->{record};
        for my $k (
            sort { int $codes->{$a}->{value} <=> int $codes->{$b}->{value} }
            grep { $_ !~ m/unassigned|private use/i }
            keys %$codes
          )
        {
            my $name = $k;
            $name =~ s/\n+//;
            my $value = int $codes->{$k}->{value};
            ok( ( grep { $value == $_ } @val ), "\%DHO_CODES has $value aka $name" );
        }
    };

    subtest 'DHCP_MESSAGE types — bootp-dhcp-parameters-2' => sub {
        plan 'no_plan';
        my $codes = $iana{registry}->{'bootp-dhcp-parameters-1'}->{registry}
          ->{'bootp-dhcp-parameters-2'}->{record};
        for my $k (
            sort { int $codes->{$a}->{value} <=> int $codes->{$b}->{value} }
            keys %$codes
          )
        {
            ok( $DHCP_MESSAGE{$k}, "\%DHCP_MESSAGE has $k" );
            ok( $DHCP_MESSAGE{$k} == int $codes->{$k}->{value}, "...and $k is " . $codes->{$k}->{value} );
        }
    };

    subtest 'NWIP_CODES — bootp-dhcp-parameters-3' => sub {
        plan 'no_plan';
        my @val = values %NWIP_CODES;
        my $codes = $iana{registry}->{'bootp-dhcp-parameters-1'}->{registry}
          ->{'bootp-dhcp-parameters-3'}->{record};
        for my $k (
            sort { int $codes->{$a}->{value} <=> int $codes->{$b}->{value} }
            grep { $_ !~ m/unassigned|private use/i }
            keys %$codes
          )
        {
            my $name = $k;
            $name =~ s/\n+//;
            my $value = int $codes->{$k}->{value};
            ok( ( grep { $value == $_ } @val ), "\%NWIP_CODES has $value aka $name" );
        }
    };

    subtest 'CCC_CODES — bootp-dhcp-parameters-4' => sub {
        plan 'no_plan';
        my @val = values %CCC_CODES;
        my $codes = $iana{registry}->{'bootp-dhcp-parameters-1'}->{registry}
          ->{'bootp-dhcp-parameters-4'}->{record};
        for my $k (
            sort { int $a->{value} <=> int $b->{value} }
            grep { $_->{description} !~ m/unassigned|private use/i } @$codes
          )
        {
            my $name = $k->{description};
            $name =~ s/\n+//;
            my $value = $k->{value};
            ok( ( grep { $value == $_ } @val ), "\%CCC_CODES has $value aka $name" );
        }
    };

    subtest 'GEOCONF_CODES — bootp-dhcp-parameters-5' => sub {
        plan 'no_plan';
        my @val = values %CCC_CODES;
        my $codes = $iana{registry}->{'bootp-dhcp-parameters-1'}->{registry}
          ->{'bootp-dhcp-parameters-5'}->{record};
        for my $k (
            sort { int $a->{value} <=> int $b->{value} }
            grep { $_->{description} !~ m/unassigned|private use/i } @$codes
          )
        {
            my $name = $k->{description};
            $name =~ s/\n+//;
            my $value = $k->{value};
            ok( ( grep { $value == $_ } @val ), "\%GEOCONF_CODES has $value aka $name" );
        }
    };

    subtest 'RELAYAGENT_CODES — bootp-dhcp-parameters-8' => sub {
        plan 'no_plan';
        my @val = values %RELAYAGENT_CODES;
        my $codes = $iana{registry}->{'bootp-dhcp-parameters-8'}->{record};
        for my $k (
            sort { int $a->{value} <=> int $b->{value} }
            grep { $_->{description} !~ m/unassigned|private use|reserved/i }
            @$codes
          )
        {
            my $name = $k->{description};
            $name =~ s/\n+//;
            my $value = $k->{value};
            ok( ( grep { $value == $_ } @val ), "\%RELAYAGENT_CODES has $value aka $name" );
        }
    };
}

1;
