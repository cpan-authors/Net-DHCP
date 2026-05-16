#!/bin/false
# ABSTRACT: Object methods to create a DHCP packet
# PODNAME: Net::DHCP
use strict;
use warnings FATAL => 'uninitialized';
use 5.8.0;

package Net::DHCP;


1;

__END__

=pod

=head1 SYNOPSIS

    use Net::DHCP::Packet;

    my $p = Net::DHCP::Packet->new(
        'Chaddr' => '000BCDEF',
        'Xid'    => 0x9F0FD,
        'Ciaddr' => '0.0.0.0',
        'Siaddr' => '0.0.0.0',
        'Hops'   => 0
    );

=head1 DESCRIPTION

Represents a DHCP packet as specified in RFC 1533, RFC 2132.

=head1 SEE ALSO

L<Net::DHCP::Options>, L<Net::DHCP::Constants>.

=cut

