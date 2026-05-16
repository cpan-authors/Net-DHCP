#!/bin/false
# PODNAME: Net::DHCP::Packet::OrderOptions
# ABSTRACT: Option ordering quirks for Net::DHCP
use strict;
use warnings FATAL => 'uninitialized';
use 5.8.0;

package Net::DHCP::Packet::OrderOptions;

use Exporter 'import';
our @EXPORT_OK = qw( reorder_options );
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

#=======================================================================
sub reorder_options {
    my @codes = @_;

    # Quirk: Intel PXE wants option 60 before option 43
    my ( $i60, $i43 );
    for ( my $i = 0; $i < @codes; $i++ ) {
        $i60 = $i if $codes[$i] == 60;
        $i43 = $i if $codes[$i] == 43;
    }
    if ( defined $i60 && defined $i43 && $i60 > $i43 ) {
        @codes[ $i60, $i43 ] = @codes[ $i43, $i60 ];
    }

    # Quirk: Cablelabs want option 82 at the very end
    my @no82 = grep { $_ != 82 } @codes;
    @codes = ( @no82, 82 ) if @no82 != @codes;

    return @codes
}

#=======================================================================

1;

=pod

=head1 SYNOPSIS

   use Net::DHCP::Packet::OrderOptions qw( reorder_options );

=head1 DESCRIPTION

Applies known option-ordering quirks to a list of option codes.
DHCP clients can be picky about option order; this module collects
those work-arounds in one place.

=head1 QUIRK WORK-AROUNDS

=over 4

=item Intel PXE

Wants option 60 (Vendor class identifier) before option 43 (Vendor-specific
options).

=item Cablelabs

Wants option 82 (Relay agent information) to always be last.

=back

=head1 METHODS

=over 4

=item reorder_options ( LIST )

Accepts a list of option-code numbers, returns them reordered to
satisfy known client quirks.  Codes not mentioned in any quirk keep
their relative order.

=back

=head1 SEE ALSO

L<Net::DHCP>, L<Net::DHCP::Packet>, L<Net::DHCP::Constants>.

=cut
