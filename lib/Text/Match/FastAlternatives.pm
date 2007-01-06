package Text::Match::FastAlternatives;

use strict;
use warnings;

our $VERSION = '0.02';
use base qw<DynaLoader>;

__PACKAGE__->bootstrap($VERSION);

1;

__END__

=head1 NAME

Text::Match::FastAlternatives - efficient search for many strings

=head1 SYNOPSIS

    use Text::Match::FastAlternatives;

    my $expletives = Text::Match::FastAlternatives->new(@naughty);
    while (my $line = <>) {
        print "Do you email your mother with that keyboard?\n"
            if $expletives->match($line);
    }

=head1 DESCRIPTION

This module allows you to search for any of a list of substrings ("keys") in a
larger string.  It is particularly efficient when the set of keys is large.

This efficiency comes at the cost of some flexibility: the keys may not contain
any control characters or non-ASCII characters; and it cannot do
case-insensitive matching.  If you want case-insensitivity, you have to fold
case yourself:

    my $expletives = Text::Match::FastAlternatives->new(
        map { lc } @naughty);
    while (my $line = <>) {
        print "Do you email your mother with that keyboard?\n"
            if $expletives->match(lc $line);
    }

This module is designed as a drop-in replacement for Perl code of the following
form:

    my $expletives_regex = join '|', map { quotemeta } @naughty;
    $expletives_regex = qr/$expletives_regex/;
    while (my $line = <>) {
        print "Do you email your mother with that keyboard?\n"
            if $line =~ $expletives_regex;
    }

Text::Match::FastAlternatives can easily perform this test a hundred times
faster than the equivalent regex, if you have enough keys.  The more keys it
searches for, the faster it gets compared to the regex.

Modules like Regexp::Trie can build an optimised version of such a regex,
designed to take advantage of the niceties of perl's regex engine.  With a
large number of keys, this module will substantially outperform even an
optimised regex like that.  In one real-world situation with 339 keys,
Regexp::Trie produced a regex that ran 857% faster than the naive regex
(according to L<Benchmark>), but using Text::Match::FastAlternatives ran 18275%
faster than the naive regex, or twenty times faster than Regexp::Trie's
optimised regex.

=head1 METHODS

=over 4

=item Text::Match::FastAlternatives->new(@keys)

Constructs a matcher that can efficiently search for all of the @keys in
parallel.  Throws an exception if any of the keys are undefined, or if any of
them contain any control characters or non-ASCII characters.

=item $matcher->match($target)

Returns a boolean value indicating whether the $target string contains any of
the keys in $matcher.

=back

=head1 CAVEATS

=head2 Subclassing

Text::Match::FastAlternatives has a C<DESTROY> method implemented in XS.  If
you write a subclass with its own destructor, you will need to invoke the base
destructor, or you will leak memory.

=head2 Perl 5.10

Perl 5.10 will contain many enhancements to the regex engine, including
built-in optimisations for regexes with many branches that contain only literal
strings.  I suspect that, for the cases where Text::Match::FastAlternatives is
currently very fast, it will also be faster than Perl 5.10's regex engine.  But
I may be wrong; if you're using Perl 5.9.4 or newer, you'd be well advised to
compare the available options on data sets you're likely to use in practice.

=head1 IMPLEMENTATION

Text::Match::FastAlternatives manages to be so fast by using a trie internally.
The time to find a match at a given position in the string (or determine that
there is no match) is independent of the number of keys being sought;
worst-case match time is linear in the length of the longest key.  Since a
match must be attempted at each position in the target string, total worst-case
search time is O(I<mn>) where I<m> is the length of the target string and I<n>
is the length of the longest key.

=head1 SEE ALSO

L<http://en.wikipedia.org/wiki/Trie>, L<Regexp::Trie>, L<Regexp::Optimizer>,
L<Regexp::Assemble>, L<perl594delta>.

=head1 AUTHOR

Aaron Crane E<lt>arc@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2006 Aaron Crane.

This library is free software; you can redistribute it and/or modify it under
the terms of the Artistic License, or (at your option) under the terms of the
GNU General Public License version 2.

=cut
