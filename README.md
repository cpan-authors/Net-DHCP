Net-DHCP version 0.7
=====================

0. DOCS/ AND T/DATA FILES WARNING
----------------------

Some files in the `docs/` directory are copied from IANA.
They may not be compatible with the MIT license. I have
included them in the tar ball as-is for the sake of reference.

Currently these files are:
- docs/bootp-dhcp-parameters.txt

Some files in t/data are copied from various sources:
- http://packetlife.net/captures/DHCP_MessageType%2010%2C11%2C12%20and%2013.cap
- http://packetlife.net/captures/DHCP_Inter_VLAN.cap (original source forgotten)
- http://uluru.ee.unsw.edu.au/~tim/zoo/f994f275.pcap
- https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=dhcp-auth.pcap.gz

Test files referencing the above:
- t/102-discover-offer-request-ack.t       — vanilla DORA
- t/103-real-nak.t                         — DHCPNAK from real capture
- t/104-offer-o90-o120.t                   — options 90, 120
- t/105-discover-offer-o122-o82.t          — options 122, 82
- t/106-discover-offer-o60-o43-o82.t       — options 60, 43, 82
- t/107-query-active-qry-unass-qry-unk.t   — DHCPLEASEACTIVE / UNASSIGNED / UNKNOWN responses to DHCPINFORM
- t/108-discover-offer-o12-o55-o61.t       — relay DORA with options 12, 55, 61

All other files are licensed as described at the bottom of this file.

Please remove the problem files if needed for distribution packaging etc.

You can fork and submit enhancements etc via https://github.com/djzort/Net-DHCP

1. DESCRIPTION
--------------

Net::DHCP is a DHCP set of classes designed to handle basic DHCP
handling. It can be used to develop either client, server or relays.
It is composed of 100% pure Perl.

The author invites feedback on Net::DHCP. If there's something you'd
like to have added, please let me know.  If you find a bug, please
send me the information described in the BUGS section below.

The original version of this module was written by Francis van Dun,
and has been deeply reorganized.

2. PREREQUISITES
----------------

Net::DHCP requires Perl 5.8.0 or higher.

3. INSTALLATION
---------------

To install this module type the following:

```
perl Makefile.PL
make
make test
make install
```

4. BUGS
-------

If you find a bug, please report it to the author along with the
following information:

 * version of Perl (output of `perl -V` is best)
 * version of Net::DHCP
 * operating system type and version
 * exact text of error message or description of problem
 * the shortest possible program that exhibits the problem

COPYRIGHT AND LICENCE
----------------------

 * Copyright (C) 2002 by Francis van Dun.
 * Copyright (C) 2005,2006 by Stephan Hadinger.
 * Copyright (C) 2010-2022 by Dean Hamstead.

```
The MIT License

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to
whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
```
