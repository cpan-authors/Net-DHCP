#!/bin/false
# PODNAME: Net::DHCP::Packet::Attributes
# Author : D. Hamstead
# Original Author: F. van Dun, S. Hadinger
# ABSTRACT: Attribute methods for Net::DHCP::Packet
use strict;
use warnings;
use 5.8.0;

package Net::DHCP::Packet::Attributes;

use Exporter 'import';
our @EXPORT_OK = qw(
  comment op htype hlen hops xid secs flags ciaddr
  ciaddrRaw yiaddr yiaddrRaw siaddr siaddrRaw giaddr giaddrRaw
  chaddr chaddrRaw sname file isDhcp padding
);
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

use Carp qw( carp );
use Net::DHCP::Packet::IPv4Utils qw( packinet unpackinet byte_len );

#=======================================================================
# comment attribute : enables transaction number identification
sub comment {
    my $self = shift;
    if (@_) { $self->{comment} = shift }
    return $self->{comment};
}

# op attribute
sub op {
    my $self = shift;
    if (@_) { $self->{op} = shift }
    return $self->{op};
}

# htype attribute
sub htype {
    my $self = shift;
    if (@_) { $self->{htype} = shift }
    return $self->{htype};
}

# hlen attribute
sub hlen {
    my $self = shift;
    if (@_) { $self->{hlen} = shift }
    if ( $self->{hlen} < 0 ) {
        carp( 'hlen must not be < 0 (currently ' . $self->{hlen} . ')' );
        $self->{hlen} = 0;
    }
    if ( $self->{hlen} > 16 ) {
        carp( 'hlen must not be > 16 (currently ' . $self->{hlen} . ')' );
        $self->{hlen} = 16;
    }
    return $self->{hlen};
}

# hops attribute
sub hops {
    my $self = shift;
    if (@_) { $self->{hops} = shift }
    return $self->{hops};
}

# xid attribute
sub xid {
    my $self = shift;
    if (@_) { $self->{xid} = shift }
    return $self->{xid};
}

# secs attribute
sub secs {
    my $self = shift;
    if (@_) { $self->{secs} = shift }
    return $self->{secs};
}

# flags attribute
sub flags {
    my $self = shift;
    if (@_) { $self->{flags} = shift }
    return $self->{flags};
}

# ciaddr attribute
sub ciaddr {
    my $self = shift;
    if (@_) { $self->{ciaddr} = packinet(shift) }
    return unpackinet( $self->{ciaddr} );
}

# ciaddr attribute, Raw version
sub ciaddrRaw {
    my $self = shift;
    if (@_) { $self->{ciaddr} = shift }
    return $self->{ciaddr};
}

# yiaddr attribute
sub yiaddr {
    my $self = shift;
    if (@_) { $self->{yiaddr} = packinet(shift) }
    return unpackinet( $self->{yiaddr} );
}

# yiaddr attribute, Raw version
sub yiaddrRaw {
    my $self = shift;
    if (@_) { $self->{yiaddr} = shift }
    return $self->{yiaddr};
}

# siaddr attribute
sub siaddr {
    my $self = shift;
    if (@_) { $self->{siaddr} = packinet(shift) }
    return unpackinet( $self->{siaddr} );
}

# siaddr attribute, Raw version
sub siaddrRaw {
    my $self = shift;
    if (@_) { $self->{siaddr} = shift }
    return $self->{siaddr};
}

# giaddr attribute
sub giaddr {
    my $self = shift;
    if (@_) { $self->{giaddr} = packinet(shift) }
    return unpackinet( $self->{giaddr} );
}

# giaddr attribute, Raw version
sub giaddrRaw {
    my $self = shift;
    if (@_) { $self->{giaddr} = shift }
    return $self->{giaddr};
}

# chaddr attribute
sub chaddr {
    my $self = shift;
    if (@_) { $self->{chaddr} = pack( 'H*', shift ) }
    return unpack( 'H*', $self->{chaddr} );
}

# chaddr attribute, Raw version
sub chaddrRaw {
    my $self = shift;
    if (@_) { $self->{chaddr} = shift }
    return $self->{chaddr};
}

# sname attribute
sub sname {
    my $self = shift;
    if (@_) { $self->{sname} = shift }
    if ( byte_len( $self->{sname} ) > 63 ) {
        carp( sprintf q|'sname' must not be > 63 bytes, (currently %d)|,
              length( $self->{sname} ));
        $self->{sname} = substr( $self->{sname}, 0, 63 );
    }
    return $self->{sname};
}

# file attribute
sub file {
    my $self = shift;
    if (@_) { $self->{file} = shift }
    if ( byte_len( $self->{file} ) > 127 ) {
        carp( sprintf q|'file' must not be > 127 bytes, (currently %d)|,
              length( $self->{file} ));
        $self->{file} = substr( $self->{file}, 0, 127 );
    }
    return $self->{file};
}

# is it DHCP or BOOTP
#   -> DHCP needs magic cookie and options
sub isDhcp {
    my $self = shift;
    if (@_) { $self->{isDhcp} = shift }
    return $self->{isDhcp};
}

# padding attribute
sub padding {
    my $self = shift;
    if (@_) { $self->{padding} = shift }
    return $self->{padding};
}

#=======================================================================

1;

=pod

=head1 SYNOPSIS

   use Net::DHCP::Packet::Attributes qw( :all );

=head1 DESCRIPTION

Provides attribute methods for Net::DHCP::Packet.

This module is not particularly useful on its own.

=head1 METHODS

=over 4

=item comment( [STRING] )

Sets or gets the comment attribute (object meta-data only)

=item op( [BYTE] )

Sets/gets the I<BOOTP opcode>.

Normal values are:

  BOOTREQUEST()
  BOOTREPLY()

=item htype( [BYTE] )

Sets/gets the I<hardware address type>.

Common value is: C<HTYPE_ETHER()> (1) = ethernet

=item hlen ( [BYTE] )

Sets/gets the I<hardware address length>. Value must be between C<0> and C<16>.

For most NIC's, the MAC address has 6 bytes.

=item hops ( [BYTE] )

Sets/gets the I<number of hops>.

This field is incremented by each encountered DHCP relay agent.

=item xid ( [INTEGER] )

Sets/gets the 32 bits I<transaction id>.

This field should be a random value set by the DHCP client.

=item secs ( [SHORT] )

Sets/gets the 16 bits I<elapsed boot time> in seconds.

=item flags ( [SHORT] )

Sets/gets the 16 bits I<flags>.

  0x8000 = Broadcast reply requested.

=item ciaddr ( [STRING] )

Sets/gets the I<client IP address>.

IP address is only accepted as a string like '10.24.50.3'.

Note: IP address is internally stored as a 4 bytes binary string.
See L<SPECIAL METHODS> below.

=item yiaddr ( [STRING] )

Sets/gets the I<your IP address>.

IP address is only accepted as a string like '10.24.50.3'.

Note: IP address is internally stored as a 4 bytes binary string.
See L<SPECIAL METHODS> below.

=item siaddr ( [STRING] )

Sets/gets the I<next server IP address>.

IP address is only accepted as a string like '10.24.50.3'.

Note: IP address is internally stored as a 4 bytes binary string.
See L<SPECIAL METHODS> below.

=item giaddr ( [STRING] )

Sets/gets the I<relay agent IP address>.

IP address is only accepted as a string like '10.24.50.3'.

Note: IP address is internally stored as a 4 bytes binary string.
See L<SPECIAL METHODS> below.

=item chaddr ( [STRING] )

Sets/gets the I<client hardware address>. Its length is given by the C<hlen> attribute.

Value is formatted as an Hexadecimal string representation.

  Example: "0010A706DFFF" for 6 bytes mac address.

Note : internal format is packed bytes string.
See L<SPECIAL METHODS> below.

=item sname ( [STRING] )

Sets/gets the "server host name". Maximum size is 63 bytes. If greater
a warning is issued.

=item file ( [STRING] )

Sets/gets the "boot file name". Maximum size is 127 bytes. If greater
a warning is issued.

=item isDhcp ( [BOOLEAN] )

Sets/gets the I<DHCP cookie>. Returns whether the cookie is valid or not,
hence whether the packet is DHCP or BOOTP.

Default value is C<1>, valid DHCP cookie.

=item padding ( [BYTES] )

Sets/gets the optional padding at the end of the DHCP packet, i.e. after
DHCP options.

Convert to hex with:
 unpack( 'H*', $obj->padding() )

=back

=head2 SPECIAL METHODS

These methods are provided for performance tuning only. They give access
to internal data representation , thus avoiding unnecessary type conversion.

=over 4

=item ciaddrRaw ( [STRING])

Sets/gets the I<client IP address> in packed 4 characters binary strings.

=item yiaddrRaw ( [STRING] )

Sets/gets the I<your IP address> in packed 4 characters binary strings.

=item siaddrRaw ( [STRING] )

Sets/gets the I<next server IP address> in packed 4 characters binary strings.

=item giaddrRaw ( [STRING] )

Sets/gets the I<relay agent IP address> in packed 4 characters binary strings.

=item chaddrRaw ( [STRING] )

Sets/gets the I<client hardware address> in packed binary string.
Its length is given by the C<hlen> attribute.

=back

=head1 SEE ALSO

L<Net::DHCP>, L<Net::DHCP::Packet>, L<Net::DHCP::Constants>.

=cut
