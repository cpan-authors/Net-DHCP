#!/bin/false
# PODNAME: Net::DHCP::Packet::IPv4Utils
# Author : D. Hamstead
# Original Author: F. van Dun, S. Hadinger
# ABSTRACT: Object methods for IPv4 in Net::DHCP
use strict;
use warnings;
use 5.8.0;

package Net::DHCP::Packet::IPv4Utils;

use Exporter 'import';
our @EXPORT_OK = qw(
    byte_len
    packinet
    packinets
    packinets_array
    unpackinet
    unpackinets
    unpackinets_array
);
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

use Carp;

#=======================================================================
# byte-length helper — contains the use bytes pragma in one place
sub byte_len {
    use bytes;
    return defined $_[0] ? length($_[0]) : 0;
}

#=======================================================================
# never failing versions of the "Socket" module functions
sub packinet {    # bullet-proof version, never complains
    my $addr = shift;

    if ( $addr && $addr =~ m/([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/ ) {
        return chr($1) . chr($2) . chr($3) . chr($4);
    }

    return "\0\0\0\0"
}

sub unpackinet {    # bullet-proof version, never complains
    my $ip = shift;
    return '0.0.0.0' unless ( $ip && byte_len($ip) == 4 );
    return
        ord( substr( $ip, 0, 1 ) ) . q|.|
      . ord( substr( $ip, 1, 1 ) ) . q|.|
      . ord( substr( $ip, 2, 1 ) ) . q|.|
      . ord( substr( $ip, 3, 1 ) );
}

sub packinets {     # multiple ip addresses, space delimited
    return join(
        q(), map { packinet($_) }
          split( /[\s\/,;]+/, shift || 0 )
    );
}

sub unpackinets {    # multiple ip addresses
    return join( q| |, map { unpackinet($_) } unpack( '(a4)*', shift || 0 ) );
}

sub packinets_array {    # multiple ip addresses, space delimited
    return unless @_;
    return join( q(), map { packinet($_) } @_ );
}

sub unpackinets_array {    # multiple ip addresses, returns an array
    return map { unpackinet($_) } unpack( '(a4)*', shift || 0 );
}

#=======================================================================

1;

=pod

=head1 SYNOPSIS

   use Net::DHCP::Packet::IPv4Utils qw( :all );

=head1 DESCRIPTION

Probably not at all useful on its own


=head2 IPv4 UTILITY METHODS

=over 4

=item byte_len ( STRING )

Returns the length of the string in bytes (uses C<use bytes>
internally). Returns 0 if the argument is undefined.

=item packinet ( STRING )

Transforms a IP address "xx.xx.xx.xx" into a packed 4 bytes string.

These are simple never failing versions of inet_ntoa and inet_aton.

=item packinets ( STRING )

Transforms a list of space delimited IP addresses into a packed bytes string.

=item packinets_array( LIST )

Transforms an array (list) of IP addresses into a packed bytes string.

=item unpackinet ( STRING )

Transforms a packed bytes IP address into a "xx.xx.xx.xx" string.

=item unpackinets ( STRING )

Transforms a packed bytes list of IP addresses into a list of
"xx.xx.xx.xx" space delimited string.

=item unpackinets_array ( STRING )

Transforms a packed bytes list of IP addresses into a array of
"xx.xx.xx.xx" strings.

=back

=head1 SEE ALSO

L<Net::DHCP::Options>, L<Net::DHCP::Constants>.

=cut
