#!/bin/false
# PODNAME: Net::DHCP::Packet::OrderOptions
# ABSTRACT: Option ordering logic for Net::DHCP
use strict;
use warnings;
use 5.8.0;

package Net::DHCP::Packet::OrderOptions;

# standard module declaration
our ( @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS );
use Exporter;
@ISA       = qw(Exporter);
@EXPORT    = qw( );
@EXPORT_OK = qw(
);
%EXPORT_TAGS = ( all => \@EXPORT_OK );

use Carp qw/ carp /;

my @order = (

# taken from isc-dhcp... i think its wrong though
53, # message type
54, # server id
51, # lease time
58, # renewal time
59, # rebinding time
56, # message
50, # requested address
92, # associated ip
118, # subnet selection
61, # client id
81, # fqdn
1, # subnet mask
3, # routers
6, # domain name servers
12, # host name

2,
4,
5,
7,
8,
9,
10,
11,
13,
14,
15,
16,
17,
18,
19,
20,
21,
22,
23,
24,
25,
26,
27,
28,
29,
30,
31,
32,
33,
34,
35,
36,
37,
38,
39,
40,
41,
42,
44,
45,
46,
47,
48,
49,
52,
55,
57,
60,
62,
63,
64,
65,
66,
67,
68,
69,
70,
71,
72,
73,
74,
75,
76,
77,
78,
79,
80,
83,
84,
85,
86,
87,
88,
89,
90,
91,
93,
94,
95,
96,
97,
98,
99,
100,
101,
102,
103,
104,
105,
106,
107,
108,
109,
110,
111,
112,
113,
114,
115,
116,
117,
119,
120,
121,
122,
123,
124,
125,
126,
127,
128,
129,
130,
131,
132,
133,
134,
135,
136,
137,
138,
139,
140,
141,
142,
143,
144,
145,
146,
147,
148,
149,
150,
151,
152,
153,
154,
155,
156,
157,
158,
159,
160,
161,
162,
163,
164,
165,
166,
167,
168,
169,
170,
171,
172,
173,
174,
175,
176,
177,
178,
179,
180,
181,
182,
183,
184,
185,
186,
187,
188,
189,
190,
191,
192,
193,
194,
195,
196,
197,
198,
199,
200,
201,
202,
203,
204,
205,
206,
207,
208,
209,
210,
211,
212,
213,
214,
215,
216,
217,
218,
219,
220,
221,
222,
223,
224,
225,
226,
227,
228,
229,
230,
231,
232,
233,
234,
235,
236,
237,
238,
239,
240,
241,
242,
243,
244,
245,
246,
247,
248,
249,
250,
251,
252,
253,
254,

# intel pxe really wants 60 before 43
43,

# Cablelabs really really wants 82 at the end
82,

);

#=======================================================================
# comment attribute : enables transaction number identification
#
#

sub optionsorder {



}

#=======================================================================

1;

=pod

=head1 SYNOPSIS

   use Net::DHCP::Packet::OrderOptions qw( :all );

=head1 DESCRIPTION

Provides sorting for optons in Net::DHCP::Packet.

This module is not particularly useful on its own.

Because DHCP clients generally suck, the order of options in the dhcp
packet actually matter. This module keeps the handling of all that
quirky madness in one place

=head1 QUIRK WORK-AROUNDS

Cable vendors really want option 82 to always be last.

Intel PXE really wants option 60 before option 43.

Minimum frame size is 300, but we only warn (carp) if its not.

=head1 METHODS

=over 4

=item optionsorder ( )

TODO This will rearrange the order of options to accommodate as many
quirky clients as possible.

=back

=head1 SEE ALSO

L<Net::DHCP>, L<Net::DHCP::Packet>, L<Net::DHCP::Constants>.

=cut
