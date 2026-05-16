#!/bin/false
# PODNAME: Net::DHCP::Packet
# Author : D. Hamstead
# Original Author: F. van Dun, S. Hadinger
# ABSTRACT: Object methods to create a DHCP packet.
use strict;
use warnings FATAL => 'uninitialized';
use 5.8.0;

package Net::DHCP::Packet;

use Carp qw( carp croak );
use Net::DHCP::Constants qw(
    :DEFAULT
    :dhcp_hashes
    :dhcp_other
    %DHO_FORMATS
    %SUBOPTION_FORMATS
);
use Net::DHCP::Packet::Attributes qw(:all);
use Net::DHCP::Packet::IPv4Utils qw(:all);
use Net::DHCP::Packet::OrderOptions qw( reorder_options );
use List::Util qw(any first none);


#=======================================================================

{

my %newargs = (

    Comment => \&comment,
    Op      => \&op,
    Htype   => \&htype,
    Hlen    => \&hlen,
    Hops    => \&hops,
    Xid     => \&xid,
    Secs    => \&secs,
    Flags   => \&flags,
    Ciaddr  => \&ciaddr,
    Yiaddr  => \&yiaddr,
    Siaddr  => \&siaddr,
    Giaddr  => \&giaddr,
    Chaddr  => \&chaddr,
    Sname   => \&sname,
    File    => \&file,
    Padding => \&padding,
    isDhcp  => \&isDhcp,

);

sub new {

    my $p = shift;
    my $class = ref($p) || $p;

    my $self = {
        options       => {},    # DHCP options
        options_order => [],    # order in which the options were added

        # defaults
        comment => undef,
        op      => BOOTREQUEST(),
        htype   => 1,    # 10mb ethernet
        hlen    => 6,    # Use 6 bytes MAC
        hops    => 0,
        xid     => 0x12345678,
        secs    => 0,
        flags   => 0,
        ciaddr  => "\0\0\0\0",
        yiaddr  => "\0\0\0\0",
        siaddr  => "\0\0\0\0",
        giaddr  => "\0\0\0\0",
        chaddr  => q||,
        sname   => q||,
        file    => q||,
        padding => q||,
        isDhcp  => 1,

    };

    bless $self, $class;

    # single argument means deserialize from binary packet buffer
    if (scalar @_ == 1) {
        $self->marshall(shift);
        return $self;
    }

    croak("new: odd number of arguments") if @_ % 2;

    # split args into attribute pairs (named keys) and option pairs (numeric codes)
    # so we can sort attributes while preserving option insertion order
    my @attr_pairs;
    my @opt_pairs;
    while (my ($k, $v) = splice @_, 0, 2) {
        if ($k =~ m/^[0-9]+$/) {
            push @opt_pairs, [$k, $v];
        }
        else {
            push @attr_pairs, [$k, $v];
        }
    }

    # process named attributes in sorted order for consistency
    for my $pair (sort { $a->[0] cmp $b->[0] } @attr_pairs) {
        my ($k, $v) = @$pair;
        if ($newargs{$k}) {
            $newargs{$k}->($self, $v);
        }
        else {
            carp sprintf('Ignoring unknown new() argument: %s', $k);
        }
    }

    # process DHCP options in original order (matters for picky clients)
    for my $pair (@opt_pairs) {
        $self->addOptionValue($pair->[0], $pair->[1]);
    }

    return $self

}

}

sub addOptionRaw {
    my ( $self, $key, $value_bin ) = @_;
    if ( $key == DHO_CLASSLESS_STATIC_ROUTE() && exists $self->{options}->{$key} ) {
        my $existing = $self->{options}->{$key};
        if (ref $existing eq 'ARRAY') {
            push @$existing, $value_bin;
        }
        else {
            $self->{options}->{$key} = [$existing, $value_bin];
        }
    }
    else {
        $self->{options}->{$key} = $value_bin;
    }
    if ( none { $_ == $key } @{ $self->{options_order} } ) {
        push @{ $self->{options_order} }, $key;
    }

    return 1
}

sub addOptionValue {
    my $self  = shift;
    my $code  = shift;    # option code
    my $value = shift;

    # my $value_bin;      # option value in binary format

    carp("addOptionValue: unknown format for code ($code)")
      unless exists $DHO_FORMATS{$code};

    my $format = $DHO_FORMATS{$code};

    if ( $format eq 'suboption' ) {
        carp 'Use addSubOptionValue to add sub options';
        return;
    }

    # decompose input value into an array
    my @values;
    if ( defined $value && $value ne q|| ) {
        @values =
          split( /[\s\/,;]+/, $value );    # array of values, split by space
    }

    # verify number of parameters
    if ( $format eq 'string' || $format eq 'csr' ) {
        @values = ($value);      # don't change format
    }
    elsif ( $format =~ m/s$/ ) { # ends with an 's', meaning any number of parameters
        ;
    }
    elsif ( $format =~ m/2$/ ) { # ends with a '2', meaning couples of parameters
        croak(
            "addOptionValue: only pairs of values expected for option '$code'")
          if ( ( @values % 2 ) != 0 );
    }
    else {                      # only one parameter
        croak("addOptionValue: exactly one value expected for option '$code'")
          if ( @values != 1 );
    }

    my %options = (

        inet   => sub { return packinet(shift) },
        inets  => sub { return packinets_array(@_) },
        inets2 => sub { return packinets_array(@_) },
        int    => sub { return pack( 'N', shift ) },
        short  => sub { return pack( 'n', shift ) },
        # 255 & trims the input to single octet
        byte   => sub { return pack( 'C', 255 & shift ) },
        bytes  => sub {
            return pack( 'C*', map { 255 & $_ } @_ );
        },
        string     => sub { return shift },
        clientid   => sub { return packclientid(shift) },
        sipserv    => sub { return packsipserv(shift) },
        csr        => sub { return packcsr(shift) },
        suboptions => sub { return packsuboptions(@_) },

    );

    #  } elsif ($format eq 'ids') {
    #    $value_bin = $values[0];
    #    # TBM bad format

    # decode the option if we know how, otherwise use the original value
    my $encoded = $options{$format} ? $options{$format}->(@values) : $value;

    # csr can return multiple chunks; store as arrayref so serialize emits
    # one option-121 instance per chunk instead of silently dropping chunks
    if (ref $encoded eq 'ARRAY' && @$encoded > 1) {
        $self->{options}->{$code} = $encoded;
        if ( none { $_ == $code } @{ $self->{options_order} } ) {
            push @{ $self->{options_order} }, $code;
        }
    }
    else {
        $self->addOptionRaw($code, $encoded);
    }

}    # end AddOptionValue

sub addSubOptionRaw {
    my ( $self, $key, $subkey, $value_bin ) = @_;
    $self->{options}->{$key}->{$subkey} = $value_bin;

    if ( none { $_ == $key } @{$self->{options_order}} ) {
        push @{ $self->{options_order} }, $key;
    }
    push @{ $self->{sub_options_order}{$key} }, ($subkey);
}

sub addSubOptionValue {

    my $self    = shift;
    my $code    = shift;    # option code
    my $subcode = shift;    # sub option code
    my $value   = shift;
    # my $value_bin;          # option value in binary format

    carp("addSubOptionValue: unknown format for code ($code)")
      unless exists $DHO_FORMATS{$code};

    carp("addSubOptionValue: not a suboption parameter for code ($code)")
      unless ( $DHO_FORMATS{$code} eq 'suboptions' );

    carp(
"addSubOptionValue: unknown format for subcode ($subcode) on code ($code)"
      )
      unless ( $DHO_FORMATS{$code} eq 'suboptions' );

    carp("addSubOptionValue: no suboptions defined for code ($code)?")
      unless exists $SUBOPTION_CODES{$code};

    carp(
        "addSubOptionValue: suboption ($subcode) not defined for code ($code)?")
      unless exists $SUBOPTION_CODES{$code}->{$subcode};

    my $format = $SUBOPTION_FORMATS{$code}->{$subcode};

    # decompose input value into an array
    my @values;
    if ( defined $value && $value ne q|| ) {
        @values =
          split( /[\s\/,;]+/, $value );    # array of values, split by space
    }

    # verify number of parameters
    if ( $format eq 'string' ) {
        @values = ($value);                # don't change format
    }
    elsif ( $format =~ m/s$/ )
    {    # ends with an 's', meaning any number of parameters
        ;
    }
    elsif ( $format =~ m/2$/ )
    {    # ends with a '2', meaning couples of parameters
        croak(
"addSubOptionValue: only pairs of values expected for option '$code'"
        ) if ( ( @values % 2 ) != 0 );
    }
    else {    # only one parameter
        croak(
            "addSubOptionValue: exactly one value expected for option '$code'")
          if ( @values != 1 );
    }

    my %options = (
        inet   => sub { return packinet(shift) },
        inets  => sub { return packinets_array(@_) },
        inets2 => sub { return packinets_array(@_) },
        int    => sub { return pack( 'N', shift ) },
        short  => sub { return pack( 'n', shift ) },
        byte   => sub { return pack( 'C', 255 & shift ) }
        ,    # 255 & trims the input to single octet
        bytes => sub {
            return pack( 'C*', map { 255 & $_ } @_ );
        },
        string => sub { return shift },
        hexa => sub { return pack( 'H*', shift ) },
    );

    #  } elsif ($format eq 'ids') {
    #    $value_bin = $values[0];
    #    # TBM bad format

    # decode the option if we know how, otherwise use the original value
    $self->addSubOptionRaw( $code, $subcode, $options{$format}
        ? $options{$format}->(@values)
        : $value );

}

sub getOptionRaw {
    my ( $self, $key ) = @_;
    return $self->{options}->{$key}
      if exists( $self->{options}->{$key} );
    return
}

sub getOptionValue {
    my $self = shift;
    my $code = shift;

    carp("getOptionValue: unknown format for code ($code)")
      unless exists( $DHO_FORMATS{$code} );

    my $format = $DHO_FORMATS{$code};
    my $subcodes;

    if (defined $format && $format eq 'suboptions') {
        $subcodes = $REV_SUBOPTION_CODES{$code} || {}
    }

    my $value_bin = $self->getOptionRaw($code);

    return unless defined $value_bin;

    # flatten accumulated chunks into a single value for decoding
    $value_bin = join('', @$value_bin) if ref $value_bin eq 'ARRAY';

    # my @values;

    # hash out these options for speed and sanity
    my %options = (
        inet   => sub { return unpackinets_array(shift) },
        inets  => sub { return unpackinets_array(shift) },
        inets2 => sub { return unpackinets_array(shift) },
        int    => sub { return unpack( 'N', shift ) },
        short  => sub { return unpack( 'n', shift ) },
        shorts => sub { return unpack( 'n*', shift ) },
        byte   => sub { return unpack( 'C', shift ) },
        bytes  => sub { return unpack( 'C*', shift ) },
        string => sub { return shift },
        clientid   => sub { return unpackclientid(shift) },
        sipserv    => sub { return unpacksipserv(shift) },
        csr        => sub { return unpackcsr(shift) },
        suboptions => sub { return unpacksuboptions(shift) },

    );

    #  } elsif ($format eq 'ids') {
    #    $values[0] = $value_bin;
    #    # TBM, bad format

    # decode the options if we know the format
    if (defined $format && $options{$format}) {
        $value_bin = join(q|, |,
        map { ref $_ ? sprintf '%s => %s', $subcodes->{$_->[0]} || $_->[0],
            do { my $v = $_->[1]; if ($v =~ m/[ ,"]/) { $v =~ s/\\/\\\\/g; $v =~ s/"/\\"/g } $v = _printable($v); $v = qq("$v") if $v =~ m/[ ,"]/; $v } : $_ }
        ( $options{$format}->($value_bin) ))
    }

    # if we cant work out the format
    return $value_bin

}   # getOptionValue

sub getSubOptionRaw {
    my ( $self, $key, $subkey ) = @_;
    return $self->{options}->{$key}->{$subkey}
      if exists( $self->{options}->{$key}->{$subkey} );
    return;
}

my %unpack = (
    inet   => sub { return unpackinets_array(shift) },
    inets  => sub { return unpackinets_array(shift) },
    inets2 => sub { return unpackinets_array(shift) },
    int    => sub { return unpack('N',          shift) },
    short  => sub { return unpack('n',          shift) },
    shorts => sub { return unpack('n*',         shift) },
    byte   => sub { return unpack('C',          shift) },
    bytes  => sub { return unpack('C*',         shift) },
    string => sub { return                     shift },
    hexa   => sub { return unpack('H*',         shift) },
);

sub getSubOptionValue {
    my $self = shift;
    my $code = shift;
    my $subcode = shift;

    croak("getSubOptionValue: unknown format for code ($code)")
      unless exists $DHO_FORMATS{$code};
    croak("getSubOptionValue: not a suboption parameter for code ($code)")
      unless $DHO_FORMATS{$code} eq 'suboptions';
    croak("getSubOptionValue: no suboptions defined for code ($code)")
      unless exists $SUBOPTION_CODES{$code};
    croak("getSubOptionValue: suboption ($subcode) not defined for code ($code)")
      unless exists $REV_SUBOPTION_CODES{$code}->{$subcode};

    my $format = exists $SUBOPTION_FORMATS{$code} ? $SUBOPTION_FORMATS{$code}->{$subcode} : undef;
    my $value_bin = $self->getSubOptionRaw($code, $subcode);
    return unless defined $value_bin;

    if ( defined $format && $unpack{$format} ) {
        return join(q|, |, $unpack{$format}->($value_bin));
    }

    return $value_bin
}    # getSubOptionValue

sub removeOption {
    my ( $self, $key ) = @_;
    if ( exists( $self->{options}->{$key} ) ) {
        my $i =
          first { $self->{options_order}->[$_] == $key }
        0 .. $#{ $self->{options_order} };
        if ( defined $i && $i < @{ $self->{options_order} } ) {
            splice @{ $self->{options_order} }, $i, 1;
        }
        delete( $self->{options}->{$key} );
    }
}

sub removeSubOption {
    my ($self, $code, $subcode) = @_;
    if (exists $self->{options}->{$code}
        && ref $self->{options}->{$code} eq 'HASH'
        && exists $self->{options}->{$code}->{$subcode}) {
        delete $self->{options}->{$code}->{$subcode};
        @{ $self->{sub_options_order}->{$code} } = grep { $_ != $subcode } @{ $self->{sub_options_order}->{$code} };
        unless (keys %{ $self->{options}->{$code} }) {
            delete $self->{options}->{$code};
            delete $self->{sub_options_order}->{$code};
            @{ $self->{options_order} } = grep { $_ != $code } @{ $self->{options_order} };
        }
    }
}

#=======================================================================
my $BOOTP_FORMAT = 'C C C C N n n a4 a4 a4 a4 a16 Z64 Z128 a*';

#my $DHCP_MIN_LENGTH = length(pack($BOOTP_FORMAT));
#=======================================================================
sub serialize {
    my ($self)  = shift;
    my $options = shift;    # reference to an options hash for special options
    my $bytes   = undef;

    $bytes = pack( $BOOTP_FORMAT,
        $self->{op},     $self->{htype},  $self->{hlen},   $self->{hops},
        $self->{xid},    $self->{secs},   $self->{flags},  $self->{ciaddr},
        $self->{yiaddr}, $self->{siaddr}, $self->{giaddr}, $self->{chaddr},
        $self->{sname},  $self->{file} );

    if ( $self->{isDhcp} ) {    # add MAGIC_COOKIE and options
        $bytes .= MAGIC_COOKIE();
        for my $key ( reorder_options( @{ $self->{options_order} } ) ) {
            if ( ref($self->{options}->{$key}) eq 'ARRAY' ) {
                for my $value ( @{$self->{options}->{$key}} ) {
                    $bytes .= pack( 'C',    $key );
                    $bytes .= pack( 'C/a*', $value );
                }
            }
            elsif ( ref($self->{options}->{$key}) eq 'HASH' ) {
                my $subbytes = q{};
                for my $subkey ( @{ $self->{sub_options_order}->{$key} } ) {
                    $subbytes .= pack( 'C',    $subkey );
                    $subbytes .= pack( 'C/a*', $self->{options}->{$key}->{$subkey} );
                }
                $bytes .= pack( 'C',    $key );
                $bytes .= pack( 'C', byte_len($subbytes) ) . $subbytes;
            }
            else {
                $bytes .= pack( 'C',    $key );
                $bytes .= pack( 'C/a*', $self->{options}->{$key} );
            }
        }
        $bytes .= pack( 'C', 255 );
    }

    $bytes .= $self->{padding};    # add optional padding

    # add padding if packet is less than minimum size
    my $min_padding = BOOTP_MIN_LEN() - byte_len($bytes);
    if ( $min_padding > 0 ) {
        $bytes .= "\0" x $min_padding;
    }

    if ( byte_len($bytes) > DHCP_MAX_MTU() ) {
        croak(  'serialize: packet too big ('
              . byte_len($bytes)
              . ' greater than max MAX_MTU ('
              . DHCP_MAX_MTU() );
    }

    # test if packet length is not bigger than DHO_DHCP_MAX_MESSAGE_SIZE
    if ( $options
        && exists( $options->{ DHO_DHCP_MAX_MESSAGE_SIZE() } ) )
    {

        # maximum packet size is specified
        my $max_message_size = $options->{ DHO_DHCP_MAX_MESSAGE_SIZE() };
        if (   ( $max_message_size >= BOOTP_MIN_LEN() )
            && ( $max_message_size < DHCP_MAX_MTU() ) )
        {

            # relevant message size
            if ( byte_len($bytes) > $max_message_size ) {
                croak(  'serialize: message is bigger than allowed ('
                      . byte_len($bytes)
                      . '), max specified :'
                      . $max_message_size );
            }
        }
    }

    return $bytes

}    # end sub serialize

#=======================================================================
sub min_len_handling {
    my ( $self, $level )  = @_;
    return $self->{min_len_handling} || 0 if @_ == 1;

    croak( sprintf q(Invalid handle level '%s', use 0, 1, or 2.), $level )
        unless $level =~ m/^[0-9]+$/ && any { $level eq $_ } 0, 1, 2;
    $self->{min_len_handling} = $level;
}

#=======================================================================
sub marshall {

    my ( $self, $buf ) = @_;
    my $opt_buf;

    my $min_len_handling = $self->min_len_handling;
    if ( $min_len_handling != 2
         && byte_len($buf) < BOOTP_ABSOLUTE_MIN_LEN()
     ) {
        my $message = sprintf
            'marshall: packet too small (%d), absolute minimum size is %d',
            byte_len($buf),
            BOOTP_ABSOLUTE_MIN_LEN();
        croak($message) unless $min_len_handling;
        warn($message);
    }
    if ( $min_len_handling != 2
         && byte_len($buf) < BOOTP_MIN_LEN()
     ) {
        my $message = sprintf
            'marshall: packet too small (%d), minimum size is %d',
            byte_len($buf),
            BOOTP_MIN_LEN();
        carp($message);
    }
    if ( byte_len($buf) > DHCP_MAX_MTU() ) {
        croak( sprintf
            'marshall: packet too big (%d), max MTU size is %s',
            byte_len($buf),
            DHCP_MAX_MTU() );
    }

    # if we are re-using this object, then we need to clear out these arrays
    delete $self->{options}
      if $self->{options};
    delete $self->{options_order}
      if $self->{options_order};
    delete $self->{sub_options_order}
      if $self->{sub_options_order};

    (
        $self->{op},     $self->{htype},  $self->{hlen},   $self->{hops},
        $self->{xid},    $self->{secs},   $self->{flags},  $self->{ciaddr},
        $self->{yiaddr}, $self->{siaddr}, $self->{giaddr}, $self->{chaddr},
        $self->{sname},  $self->{file},   $opt_buf
    ) = unpack( $BOOTP_FORMAT, $buf );

    $self->{isDhcp} = 0;    # default to BOOTP
    if (   ( byte_len( $opt_buf ) > 4 )
        && ( substr( $opt_buf, 0, 4 ) eq MAGIC_COOKIE() ) )
    {

        # it is definitely DHCP
        $self->{isDhcp} = 1;

        my $pos   = 4;     # Skip magic cookie
        my $total = length($opt_buf);
        my $type;

        while ( $pos < $total ) {

            $type = ord( substr( $opt_buf, $pos++, 1 ) );
            next if ( $type eq DHO_PAD() );  # Skip padding bytes
            last if ( $type eq DHO_END() );  # Type 'FF' signals end of options.
            my $len = ord( substr( $opt_buf, $pos++, 1 ) );
            $len = $total - $pos if $pos + $len > $total;
            my $option = substr( $opt_buf, $pos, $len );
            $pos += $len;
            $self->addOptionRaw( $type, $option );

        }

        # verify that we ended with an "END" code
        if ( $type != DHO_END() ) {
            croak('marshall: unexpected end of options');
        }

        # put remaining bytes in the padding attribute
        if ( $pos < $total ) {
            $self->{padding} = substr( $opt_buf, $pos, $total - $pos );
        }
        else {
            $self->{padding} = q||;
        }

    }
    else {

        # in bootp, everything is padding
        $self->{padding} = $opt_buf;

    }

    return $self

}   # end sub marshall

#=======================================================================
sub toString {
    my $self = shift;
    my $s;

    $s .= sprintf( "comment = %s\n", $self->comment() )
      if defined( $self->comment() );
    $s .= sprintf(
        "op = %s\n",
        (
            exists( $REV_BOOTP_CODES{ $self->op() } )
              && $REV_BOOTP_CODES{ $self->op() }
          )
          || $self->op()
    );
    $s .= sprintf(
        "htype = %s\n",
        (
            exists( $REV_HTYPE_CODES{ $self->htype() } )
              && $REV_HTYPE_CODES{ $self->htype() }
          )
          || $self->htype()
    );
    $s .= sprintf( "hlen = %s\n",   $self->hlen() );
    $s .= sprintf( "hops = %s\n",   $self->hops() );
    $s .= sprintf( "xid = %x\n",    $self->xid() );
    $s .= sprintf( "secs = %i\n",   $self->secs() );
    $s .= sprintf( "flags = %x\n",  $self->flags() );
    $s .= sprintf( "ciaddr = %s\n", $self->ciaddr() );
    $s .= sprintf( "yiaddr = %s\n", $self->yiaddr() );
    $s .= sprintf( "siaddr = %s\n", $self->siaddr() );
    $s .= sprintf( "giaddr = %s\n", $self->giaddr() );
    $s .= sprintf( "chaddr = %s\n",
        substr( $self->chaddr(), 0, 2 * $self->hlen() ) );
    $s .= sprintf( "sname = %s\n", $self->sname() );
    $s .= sprintf( "file = %s\n",  $self->file() );
    $s .= "Options : \n";

    for my $key ( @{ $self->{options_order} } ) {
        my $value;

        if ( exists $DHO_FORMATS{$key} && $DHO_FORMATS{$key} eq 'suboptions' ) {
            for my $subkey ( @{ $self->{sub_options_order}->{$key} } ) {
                my $subvalue;
                eval { $subvalue = join(q| |, $self->getSubOptionValue($key, $subkey)) };
                if ($@) {
                    my $raw = $self->getSubOptionRaw($key, $subkey);
                    $subvalue = defined $raw ? unpack('H*', $raw) : '';
                }
                $subvalue = _printable($subvalue);
                $s .= sprintf("   %s(%d) = %s\n",
                    exists $SUBOPTION_CODES{$key} && exists $REV_SUBOPTION_CODES{$key}{$subkey}
                      ? $REV_SUBOPTION_CODES{$key}{$subkey} : '',
                    $key, $subvalue);
            }
            $value = 'see above';
        }
        else {
            $value = $self->getOptionValue($key);
            $value = $self->getOptionRaw($key) unless defined $value;
            if ( defined $value ) {
                if ($key == DHO_DHCP_MESSAGE_TYPE() && exists $REV_DHCP_MESSAGE{$value}) {
                    $value = $REV_DHCP_MESSAGE{$value};
                }
                $value = _printable($value);
            }
            $value = '' unless defined $value;
        }

        $s .= sprintf(" %s(%d) = %s\n",
            exists $REV_DHO_CODES{$key} ? $REV_DHO_CODES{$key} : '',
            $key, $value);
    }
    $s .= sprintf(
        "padding [%s] = %s\n",
        length( $self->{padding} ),
        unpack( 'H*', $self->{padding} )
    );

    return $s

}   # end toString

#=======================================================================
# internal utility functions

sub _printable {
    my $str = shift;
    $str =~ s/([[:^print:]])/ sprintf q[\x%02X], ord $1 /eg;
    return $str;
}

sub packsuboptions {
    my @relay_opt = @_
      or return;

    my $buf = '';
    for my $opt (@relay_opt) {
        my $value = pack( 'C/a*', $opt->[1]);
        $buf .= pack( 'C', $opt->[0])
             . pack( 'C', length($value))
             . $value;
    }

    return pack( 'C', length($buf) ) . $buf
}

sub unpacksuboptions {

    my $opt_buf = shift;
    return unless defined $opt_buf && length $opt_buf;

    my @relay_opt;
    my $pos   = 0;
    my $total = byte_len($opt_buf);

    while ( $pos < $total ) {
        my $type = ord( substr( $opt_buf, $pos++, 1 ) );
        my $len  = ord( substr( $opt_buf, $pos++, 1 ) );
        $len = $total - $pos if $pos + $len > $total;
        my $option = substr( $opt_buf, $pos, $len );
        $pos += $len;
        push @relay_opt, [ $type, $option ];
    }

    return @relay_opt

}


sub packclientid {
    my $clientid = shift;
    return unless defined $clientid && length $clientid;

    if ($clientid =~ m/^[0-9a-fA-F]{2}(?:[0-9a-fA-F]{2})*$/) {
        return pack('C', 1) . pack('H*', $clientid);
    }
    return pack('C', 0) . $clientid;
}

sub unpackclientid {

    my $clientid = shift;
    return unless defined $clientid && length $clientid;


## See https://tools.ietf.org/html/rfc2132#section-9.14
## See also https://tools.ietf.org/html/rfc4361
#   The code for this option is 61, and its minimum length is 2.
#
#   Code   Len   Type  Client-Identifier
#   +-----+-----+-----+-----+-----+---
#   |  61 |  n  |  t1 |  i1 |  i2 | ...
#   +-----+-----+-----+-----+-----+---
#

    my $type = unpack('C',substr( $clientid, 0, 1 ));

    if ($type == 0) { # fqdn i.e. text
        return substr( $clientid, 1, length($clientid) )
    }

    # Types from here on down are from 'Address Resolution Protocol' section in RFC1700
    if ($type == 1) { # ethernet
        return unpack('H*',substr( $clientid, 1, length($clientid) ))
    }

    # Copied here for future reference
    # Number Hardware Type (hrd)                           References
    # ------ -----------------------------------           ----------
    #     1 Ethernet (10Mb)                                    [JBP]
    #     2 Experimental Ethernet (3Mb)                        [JBP]
    #     3 Amateur Radio AX.25                                [PXK]
    #     4 Proteon ProNET Token Ring                          [JBP]
    #     5 Chaos                                              [GXP]
    #     6 IEEE 802 Networks                                  [JBP]
    #     7 ARCNET                                             [JBP]
    #     8 Hyperchannel                                       [JBP]
    #     9 Lanstar                                             [TU]
    #    10 Autonet Short Address                             [MXB1]
    #    11 LocalTalk                                         [JKR1]
    #    12 LocalNet (IBM PCNet or SYTEK LocalNET)             [JXM]
    #    13 Ultra link                                        [RXD2]
    #    14 SMDS                                              [GXC1]
    #    15 Frame Relay                                        [AGM]
    #    16 Asynchronous Transmission Mode (ATM)              [JXB2]
    #    17 HDLC                                               [JBP]
    #    18 Fibre Channel                            [Yakov Rekhter]
    #    19 Asynchronous Transmission Mode (ATM)      [Mark Laubach]
    #    20 Serial Line                                        [JBP]
    #    21 Asynchronous Transmission Mode (ATM)              [MXB1]

    return $clientid

}

sub packsipserv {
    my $sipserv = shift;
    return unless defined $sipserv && length $sipserv;

    if ($sipserv =~ m/^[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:\s+[0-9]{1,3}(?:\.[0-9]{1,3}){3})*$/) {
        return pack('C', 1) . packinets($sipserv);
    }
    return pack('C', 0) . $sipserv;
}

sub unpacksipserv {

    my $sipserv = shift;
    return unless defined $sipserv && length $sipserv;

    my $type = unpack('C',substr( $sipserv, 0, 1 ));

    if ($type == 0) { # text
        return substr( $sipserv, 1 )
    }
    if ($type == 1) { # ipv4
        return unpackinets(substr( $sipserv, 1, length($sipserv) ))
    }

    return $sipserv

}

sub packcsr {
    my $routes = shift;
    return [''] unless defined $routes;

    if (!ref $routes) {
        my @tokens = split ' ', $routes;
        $routes = [];
        while (@tokens >= 2) {
            push @$routes, [shift(@tokens), shift(@tokens)];
        }
    }

    my $results = [ '' ];

    for my $pair ( @$routes ) {
        push @$results, ''
            if (length($results->[-1]) > 255 - 9);

        my ($ip, $mask) = split /\//, $pair->[0];
        $mask = 32
                unless (defined($mask) && $mask <= 32);

        my $addr = packinet($ip);
        $addr = substr $addr, 0, int(($mask - 1)/8 + 1);

        $results->[-1] .= pack('C', $mask) . $addr;
        $results->[-1] .= packinet($pair->[1]);
    }

    return $results;
}

sub unpackcsr {
    my $csr = shift;
    return unless defined $csr && length $csr;

    my @routes;
    my $pos = 0;
    my $len = length($csr);

    while ($pos < $len) {
        my $mask = ord(substr($csr, $pos, 1));
        $pos++;

        if ($mask > 32) {
            last;
        }

        my $addr_bytes = $mask ? int(($mask - 1) / 8) + 1 : 0;

        if ($pos + $addr_bytes > $len) {
            carp('unpackcsr: truncated CSR option (address bytes)');
            last;
        }

        my $addr_str;
        if ($addr_bytes) {
            my $addr_raw = substr($csr, $pos, $addr_bytes);
            $pos += $addr_bytes;
            my $padded = $addr_raw . ("\x00" x (4 - $addr_bytes));
            $addr_str = join('.', ord(substr($padded, 0, 1)), ord(substr($padded, 1, 1)),
                                  ord(substr($padded, 2, 1)), ord(substr($padded, 3, 1))) . "/$mask";
        }
        else {
            $addr_str = "0.0.0.0/$mask";
        }

        if ($pos + 4 > $len) {
            carp('unpackcsr: truncated CSR option (router bytes)');
            last;
        }

        my $router_raw = substr($csr, $pos, 4);
        $pos += 4;
        my $router_str = join('.', ord(substr($router_raw, 0, 1)), ord(substr($router_raw, 1, 1)),
                                   ord(substr($router_raw, 2, 1)), ord(substr($router_raw, 3, 1)));
        push @routes, $addr_str, $router_str;
    }

    return @routes;
}

#=======================================================================

1;

=pod

=head1 SYNOPSIS

    use Net::DHCP::Packet;

    my $p = Net::DHCP::Packet->new(

        'Chaddr' => '000BCDEF',
        'Xid' => 0x9F0FD,
        'Ciaddr' => '0.0.0.0',
        'Siaddr' => '0.0.0.0',
        'Hops' => 0

    );

=head1 DESCRIPTION

Represents a DHCP packet as specified in RFC 1533, RFC 2132.

=head1 CONSTRUCTOR

Create a new C<Net::DHCP::Packet> object from a raw buffer, a set of named arguments, or with no arguments for defaults.

=over 4

=item new()

=item new( BUFFER )

=item new( ARG => VALUE, ARG => VALUE... )

Creates an C<Net::DHCP::Packet> object, which can be used to send or receive
DHCP network packets. BOOTP is not supported.

Without argument, a default empty packet is created.

    $packet = Net::DHCP::Packet();

A C<BUFFER> argument is interpreted as a binary buffer like one provided
by the socket C<recv()> function. if the packet is malformed, a fatal error
is issued.

    use IO::Socket::INET;
    use Net::DHCP::Packet;

    $sock = IO::Socket::INET->new(LocalPort => 67, Proto => "udp", Broadcast => 1)
            or die "socket: $@";

    while ($sock->recv($newmsg, 1024)) {
        $packet = Net::DHCP::Packet->new($newmsg);
        print $packet->toString();
    }

To create a fresh new packet C<new()> takes arguments as a key-value pairs :

   ARGUMENT   FIELD      OCTETS       DESCRIPTION
   --------   -----      ------       -----------

   Op         op            1  Message op code / message type.
                               1 = BOOTREQUEST, 2 = BOOTREPLY
   Htype      htype         1  Hardware address type, see ARP section in "Assigned
                               Numbers" RFC; e.g., '1' = 10mb ethernet.
   Hlen       hlen          1  Hardware address length (e.g.  '6' for 10mb
                               ethernet).
   Hops       hops          1  Client sets to zero, optionally used by relay agents
                               when booting via a relay agent.
   Xid        xid           4  Transaction ID, a random number chosen by the
                               client, used by the client and server to associate
                               messages and responses between a client and a
                               server.
   Secs       secs          2  Filled in by client, seconds elapsed since client
                               began address acquisition or renewal process.
   Flags      flags         2  Flags (see figure 2).
   Ciaddr     ciaddr        4  Client IP address; only filled in if client is in
                               BOUND, RENEW or REBINDING state and can respond
                               to ARP requests.
   Yiaddr     yiaddr        4  'your' (client) IP address.
   Siaddr     siaddr        4  IP address of next server to use in bootstrap;
                               returned in DHCPOFFER, DHCPACK by server.
   Giaddr     giaddr        4  Relay agent IP address, used in booting via a
                               relay agent.
   Chaddr     chaddr       16  Client hardware address.
   Sname      sname        64  Optional server host name, null terminated string.
   File       file        128  Boot file name, null terminated string; "generic"
                               name or null in DHCPDISCOVER, fully qualified
                               directory-path name in DHCPOFFER.
   IsDhcp     isDhcp        4  Controls whether the packet is BOOTP or DHCP.
                               DHCP contains the "magic cookie" of 4 bytes.
                               0x63 0x82 0x53 0x63.
   DHO_*code                   Optional parameters field.  See the options
                               documents for a list of defined options.
                               See Net::DHCP::Constants.
   Padding    padding       *  Optional padding at the end of the packet

See below methods for values and syntax description.

Note: DHCP options are created in the same order as key-value pairs.

=back

=head1 METHODS

=head2 ATTRIBUTE METHODS

See L<Net::DHCP::Packet::Attributes>


=head2 DHCP OPTIONS METHODS

This section describes how to read or set DHCP options. Methods are given
in two flavours : (i) text format with automatic type conversion,
(ii) raw binary format.

Standard way of accessing options is through automatic type conversion,
described in the L<DHCP OPTIONS TYPES> section. Only a subset of types
is supported, mainly those defined in rfc 2132.

Raw binary functions are provided for pure performance optimization,
and for unsupported types manipulation.

=over 4

=item addOptionValue( CODE, VALUE )

Adds a DHCP option field. Common code values are listed in
C<Net::DHCP::Constants> C<DHO_>*.

Values are automatically converted according to their data types,
depending on their format as defined by RFC 2132.
Please see L<DHCP OPTIONS TYPES> for supported options and corresponding
formats.

If you need access to the raw binary values, please use C<addOptionRaw()>.

    $pac = Net::DHCP::Packet->new();
    $pac->addOption(DHO_DHCP_MESSAGE_TYPE(), DHCPINFORM());
    $pac->addOption(DHO_NAME_SERVERS(), "10.0.0.1", "10.0.0.2"));

=item addSubOptionValue( CODE, SUBCODE, VALUE )

Adds a DHCP sub-option field. Common code values are listed in
C<Net::DHCP::Constants> C<SUBOPTION_>*.

Values are automatically converted according to their data types,
depending on their format as defined by RFC 2132.
Please see L<DHCP OPTIONS TYPES> for supported options and corresponding
formats.

If you need access to the raw binary values, please use C<addSubOptionRaw()>.

    $pac = Net::DHCP::Packet->new();
    $pac->addSubOptionValue(
        DHO_DHCP_AGENT_OPTIONS(),
        RAI_CIRCUIT_ID(),
        "my-circuit-id"
    );
    $pac->addSubOptionValue(
        DHO_DHCP_AGENT_OPTIONS(),
        RAI_REMOTE_ID(),
        "my-remote-id"
    );

=item getOptionValue( CODE )

Returns the value of a DHCP option.

Automatic type conversion is done according to their data types,
as defined in RFC 2132.
Please see L<DHCP OPTIONS TYPES> for supported options and corresponding
formats.

If you need access to the raw binary values, please use C<getOptionRaw()>.

Return value is either a string or an array, depending on the context.

    $ip  = $pac->getOptionValue(DHO_SUBNET_MASK());
    $ips = $pac->getOptionValue(DHO_NAME_SERVERS());

=item addOptionRaw( CODE, VALUE )

Adds a DHCP OPTION provided in packed binary format.
Please see corresponding RFC for manual type conversion.

=item addSubOptionRaw( CODE, SUBCODE, VALUE )

Adds a DHCP SUB-OPTION provided in packed binary format.
Please see corresponding RFC for manual type conversion.

=item getOptionRaw( CODE )

Gets a DHCP OPTION provided in packed binary format.
Please see corresponding RFC for manual type conversion.

=item getSubOptionRaw( CODE, SUBCODE )

Gets a DHCP SUB-OPTION provided in packed binary format.
Please see corresponding RFC for manual type conversion.

=item getSubOptionValue()

This is an empty stub for now

=item removeSubOption()

This is an empty stub for now

=item I<removeOption( CODE )>

Remove option from option list.

=item I<packclientid( VALUE )>

returns the packed Client-identifier.

Auto-detects format: even-length hex strings (e.g. C<"0010A706DFFF">)
are packed as type 1 (MAC), plain text as type 0 (FQDN).

See L<https://tools.ietf.org/html/rfc2132#section-9.14>

See also L<https://tools.ietf.org/html/rfc4361>

=item I<unpackclientid>

returns the unpacked clientid.

Decodes:
 type 0 as a string
 type 1 as a mac address (hex string)
 everything is passed through

See L<https://tools.ietf.org/html/rfc2132#section-9.14>

See also L<https://tools.ietf.org/html/rfc4361>

=item I<packsipserv( VALUE )>

returns the packed sip server field.

Auto-detects format: IP addresses are packed as type 1,
domain names as type 0.

See L<https://tools.ietf.org/html/rfc3361>

=item I<unpacksipserv>

returns the unpacked sip server.

Decodes:
 type 0 as a domain name string
 type 1 as space-separated IPv4 addresses (e.g. C<"10.0.0.1 192.168.1.1">)
 everything else is passed through

=item I<packcsr( ARRAYREF )>

returns the packed Classless Static Route option built from a list of
CIDR prefix/gateway pairs. Each pair is C<[prefix, gateway]> where
C<prefix> is a CIDR string like C<"10.0.0.0/8"> and C<gateway> is an
IPv4 string like C<"10.0.0.1">.

=item I<unpackcsr>

Returns the unpacked Classless Static Route as a list of alternating
prefix/mask and gateway strings (e.g. C<"10.0.0.0/8", "10.0.0.1">).

=item I<addOption( CODE, VALUE )>

I<Removed as of version 0.60. Please use C<addOptionRaw()> instead.>

=item I<getOption( CODE )>

I<Removed as of version 0.60. Please use C<getOptionRaw()> instead.>

=back

=head2 DHCP OPTIONS TYPES

This section describes supported option types (cf. RFC 2132).

For unsupported data types, please use C<getOptionRaw()> and
C<addOptionRaw> to manipulate binary format directly.

=over 4

=item dhcp message type

Only supported for DHO_DHCP_MESSAGE_TYPE (053) option.
Converts a integer to a single byte.

Option code for 'dhcp message' format:

    (053) DHO_DHCP_MESSAGE_TYPE

Example:

    $pac->addOptionValue(DHO_DHCP_MESSAGE_TYPE(), DHCPINFORM());

=item string

Pure string attribute, no type conversion.

Option codes for 'string' format:

    (012) DHO_HOST_NAME
    (014) DHO_MERIT_DUMP
    (015) DHO_DOMAIN_NAME
    (017) DHO_ROOT_PATH
    (018) DHO_EXTENSIONS_PATH
    (047) DHO_NETBIOS_SCOPE
    (056) DHO_DHCP_MESSAGE
    (060) DHO_VENDOR_CLASS_IDENTIFIER
    (062) DHO_NWIP_DOMAIN_NAME
    (064) DHO_NIS_DOMAIN
    (065) DHO_NIS_SERVER
    (066) DHO_TFTP_SERVER
    (067) DHO_BOOTFILE
    (086) DHO_NDS_TREE_NAME
    (098) DHO_USER_AUTHENTICATION_PROTOCOL

Example:

    $pac->addOptionValue(DHO_TFTP_SERVER(), "foobar");

=item single ip address

Exactly one IP address, in dotted numerical format '192.168.1.1'.

Option codes for 'single ip address' format:

    (001) DHO_SUBNET_MASK
    (016) DHO_SWAP_SERVER
    (028) DHO_BROADCAST_ADDRESS
    (032) DHO_ROUTER_SOLICITATION_ADDRESS
    (050) DHO_DHCP_REQUESTED_ADDRESS
    (054) DHO_DHCP_SERVER_IDENTIFIER
    (118) DHO_SUBNET_SELECTION

Example:

    $pac->addOptionValue(DHO_SUBNET_MASK(), "255.255.255.0");

=item multiple ip addresses

Any number of IP address, in dotted numerical format '192.168.1.1'.
Empty value allowed.

Option codes for 'multiple ip addresses' format:

    (003) DHO_ROUTERS
    (004) DHO_TIME_SERVERS
    (005) DHO_NAME_SERVERS
    (006) DHO_DOMAIN_NAME_SERVERS
    (007) DHO_LOG_SERVERS
    (008) DHO_COOKIE_SERVERS
    (009) DHO_LPR_SERVERS
    (010) DHO_IMPRESS_SERVERS
    (011) DHO_RESOURCE_LOCATION_SERVERS
    (041) DHO_NIS_SERVERS
    (042) DHO_NTP_SERVERS
    (044) DHO_NETBIOS_NAME_SERVERS
    (045) DHO_NETBIOS_DD_SERVER
    (048) DHO_FONT_SERVERS
    (049) DHO_X_DISPLAY_MANAGER
    (068) DHO_MOBILE_IP_HOME_AGENT
    (069) DHO_SMTP_SERVER
    (070) DHO_POP3_SERVER
    (071) DHO_NNTP_SERVER
    (072) DHO_WWW_SERVER
    (073) DHO_FINGER_SERVER
    (074) DHO_IRC_SERVER
    (075) DHO_STREETTALK_SERVER
    (076) DHO_STDA_SERVER
    (085) DHO_NDS_SERVERS

Example:

    $pac->addOptionValue(DHO_NAME_SERVERS(), "10.0.0.11 192.168.1.10");

=item pairs of ip addresses

Even number of IP address, in dotted numerical format '192.168.1.1'.
Empty value allowed.

Option codes for 'pairs of ip address' format:

    (021) DHO_POLICY_FILTER
    (033) DHO_STATIC_ROUTES

Example:

    $pac->addOptionValue(DHO_STATIC_ROUTES(), "10.0.0.1 192.168.1.254");

=item byte, short and integer

Numerical value in byte (8 bits), short (16 bits) or integer (32 bits)
format.

Option codes for 'byte (8)' format:

    (019) DHO_IP_FORWARDING
    (020) DHO_NON_LOCAL_SOURCE_ROUTING
    (023) DHO_DEFAULT_IP_TTL
    (027) DHO_ALL_SUBNETS_LOCAL
    (029) DHO_PERFORM_MASK_DISCOVERY
    (030) DHO_MASK_SUPPLIER
    (031) DHO_ROUTER_DISCOVERY
    (034) DHO_TRAILER_ENCAPSULATION
    (036) DHO_IEEE802_3_ENCAPSULATION
    (037) DHO_DEFAULT_TCP_TTL
    (039) DHO_TCP_KEEPALIVE_GARBAGE
    (046) DHO_NETBIOS_NODE_TYPE
    (052) DHO_DHCP_OPTION_OVERLOAD
    (116) DHO_AUTO_CONFIGURE

Option codes for 'short (16)' format:

    (013) DHO_BOOT_SIZE
    (022) DHO_MAX_DGRAM_REASSEMBLY
    (026) DHO_INTERFACE_MTU
    (057) DHO_DHCP_MAX_MESSAGE_SIZE

Option codes for 'integer (32)' format:

    (002) DHO_TIME_OFFSET
    (024) DHO_PATH_MTU_AGING_TIMEOUT
    (035) DHO_ARP_CACHE_TIMEOUT
    (038) DHO_TCP_KEEPALIVE_INTERVAL
    (051) DHO_DHCP_LEASE_TIME
    (058) DHO_DHCP_RENEWAL_TIME
    (059) DHO_DHCP_REBINDING_TIME

Examples:

    $pac->addOptionValue(DHO_DHCP_OPTION_OVERLOAD(), 3);
    $pac->addOptionValue(DHO_INTERFACE_MTU(), 1500);
    $pac->addOptionValue(DHO_DHCP_RENEWAL_TIME(), 24*60*60);

=item multiple bytes, shorts

A list a bytes or shorts.

Option codes for 'multiple bytes (8)' format:

    (055) DHO_DHCP_PARAMETER_REQUEST_LIST

Option codes for 'multiple shorts (16)' format:

    (025) DHO_PATH_MTU_PLATEAU_TABLE
    (117) DHO_NAME_SERVICE_SEARCH

Examples:

    $pac->addOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST(),  "1 3 6 12 15 28 42 72");

=back

=head2 SERIALIZATION METHODS

=over 4

=item serialize()

Converts a Net::DHCP::Packet to a string, ready to put on the network.

=item marshall( BYTES )

The inverse of serialize. Converts a string, presumably a
received UDP packet, into a Net::DHCP::Packet.

If the packet is malformed, a fatal error is produced.

=back

=head2 HELPER METHODS

=over 4

=item toString()

Returns a textual representation of the packet, for debugging.

=item packsuboptions( LIST )

Transforms an list of lists into packed option.
For option 43 (vendor specific), 82 (relay agent) etc.

=item unpacksuboptions( STRING )

Unpacks sub-options to a list of lists

=item min_len_handling( LEVEL )

By default, the level is set to 0. If the packet is shorter than the
minimum C<BOOTP_MIN_LEN>, a warning is issued; if it is shorter than
the absolute minimum C<BOOTP_ABSOLUTE_MIN_LEN>, an exception is
thrown.

If the level is set to 1, even the absolute minimum just warns.

Setting the level to 2 means the packet length checks are skipped
altogether.

Without a parameter, the method returns the current level.

=back

See also L<Net::DHCP::Packet::IPv4Utils>

=head1 EXAMPLES

Sending a simple DHCP packet:

  #!/usr/bin/perl
  # Simple DHCP client - sending a broadcasted DHCP Discover request

  use IO::Socket::INET;
  use Net::DHCP::Packet;
  use Net::DHCP::Constants;

  # create DHCP Packet
  $discover = Net::DHCP::Packet->new(
      Xid                      => int(rand(0xFFFFFFFF)),
      Flags                    => 0x8000,
      DHO_DHCP_MESSAGE_TYPE()  => DHCPDISCOVER(),
  );

  # send packet
  $handle = IO::Socket::INET->new(
      Proto     => 'udp',
      Broadcast => 1,
      PeerPort  => '67',
      LocalPort => '68',
      PeerAddr  => '255.255.255.255',
  ) or die "socket: $@";

  $handle->send($discover->serialize())
      or die "Error sending broadcast inform: $!\n";

Sniffing DHCP packets.

  #!/usr/bin/perl
  # Simple DHCP server - listen to DHCP packets and print them

  use IO::Socket::INET;
  use Net::DHCP::Packet;

  $sock = IO::Socket::INET->new(
      LocalPort => 67,
      Proto     => 'udp',
      Broadcast => 1,
  ) or die "socket: $@";

  while ($sock->recv($newmsg, 1024)) {
      $packet = Net::DHCP::Packet->new($newmsg);
      print STDERR $packet->toString();
  }

Sending a LEASEQUERY (provided by John A. Murphy).

  #!/usr/bin/perl
  # Simple DHCP client - send a LeaseQuery (by IP) and receive the response

  use IO::Socket::INET;
  use Net::DHCP::Packet;
  use Net::DHCP::Constants;

  $usage = "usage: $0 DHCP_SERVER_IP DHCP_CLIENT_IP\n";
  $ARGV[1] or die $usage;

  # create a socket
  $handle = IO::Socket::INET->new(
      Proto     => 'udp',
      Broadcast => 1,
      PeerPort  => '67',
      LocalPort => '67',
      PeerAddr  => $ARGV[0],
  ) or die "socket: $@";

  # create DHCP Packet
  $inform = Net::DHCP::Packet->new(
      Op                       => BOOTREQUEST(),
      Htype                    => 0,
      Hlen                     => 0,
      Ciaddr                   => $ARGV[1],
      Giaddr                   => $handle->sockhost(),
      Xid                      => int(rand(0xFFFFFFFF)),
      DHO_DHCP_MESSAGE_TYPE()  => DHCPLEASEQUERY,
  );

  # send request
  $handle->send($inform->serialize())
      or die "Error sending LeaseQuery: $!\n";

  # receive response
  $handle->recv($newmsg, 1024) or die;
  $packet = Net::DHCP::Packet->new($newmsg);
  print $packet->toString();

A simple DHCP Server is provided in the "examples" directory. It is composed of
"dhcpd.pl" a *very* simple server example, and "dhcpd_test.pl" a simple tester for
this server.

=head1 SEE ALSO

L<Net::DHCP::Constants>, L<Net::DHCP::Packet::IPv4Utils>,
L<Net::DHCP::Packet::Attributes>, L<Net::DHCP::Packet::OrderOptions>.

=cut
