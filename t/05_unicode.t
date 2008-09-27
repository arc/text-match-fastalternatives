#! /usr/bin/perl

use strict;
use warnings;

use Test::More;

BEGIN {
    if ($] >= 5.008) {
        binmode Test::More->builder->output,         ':utf8';
        binmode Test::More->builder->failure_output, ':utf8';
    }
}

my @cities = read_utf8_lines('t/data/cities.txt');
my @yapc   = read_utf8_lines('t/data/yapc.txt');

plan tests => 1 + 2 * @cities;

use_ok('Text::Match::FastAlternatives');

my $tmfa   = Text::Match::FastAlternatives->new(@yapc);
my $tmfa_i = Text::Match::FastAlternatives->new(map { lc } @yapc);
my $rx     = build_regex(0, @yapc);
my $rx_i   = build_regex(1, @yapc);

for my $line (@cities) {
    my $match_tmfa   = $tmfa->match($line);
    my $match_rx     = $line =~ $rx;
    ok($match_tmfa && $match_rx || !$match_tmfa && !$match_rx,
        "same case-sensitive result for '$line'");
    my $match_tmfa_i = $tmfa_i->match(lc $line);
    my $match_rx_i   = $line =~ $rx_i;
    ok($match_tmfa_i && $match_rx_i || !$match_tmfa_i && !$match_rx_i,
        "same case-insensitive result for '$line'");
}

sub build_regex {
    my ($caseless, @items) = @_;
    my $rx = join '|', map { quotemeta } @items;
    return $caseless ? qr/$rx/i : qr/$rx/;
}

sub read_utf8_lines {
    my ($filename) = @_;
    return read_raw_lines($filename, '<:utf8')
        if $] >= 5.008;
    my @lines = read_raw_lines($filename, '<');
    $_ = decode_utf8($_) for @lines;
    return @lines;
}

sub read_raw_lines {
    my ($filename, $mode) = @_;
    open my $fh, $mode, $filename
        or die "can't open $filename for reading: $!\n";
    my @lines = <$fh>;
    chomp @lines;
    return @lines;
}

sub top_set_bits {
    my ($i) = @_;
    my @masks = (0, 0b1000_0000, 0b1100_0000, 0b1110_0000, 0b1111_0000,
                    0b1111_1000, 0b1111_1100, 0b1111_1110, 0b1111_1111);
    for my $n (0 .. 7) {
        return $n if ($i & $masks[$n + 1]) == $masks[$n];
    }
    return 8;
}

sub utf8_char {
    my ($start, @bytes) = @_;
    for (@bytes) {
        $start <<= 6;
        $start  |= $_ & 0b11_1111;
    }
    return $start;
}

sub decode_utf8 {
    my ($encoded) = @_;
    my @chars;
    my @bytes = unpack 'C*', $encoded;
    while (@bytes) {
        my $byte = shift @bytes;
        my $top = top_set_bits($byte);
        if ($top == 0) {
            push @chars, $byte;
        }
        elsif ($top == 2) {
            push @chars, utf8_char($byte & 0b1_1111, shift @bytes);
        }
        elsif ($top == 3) {
            push @chars, utf8_char($byte & 0b1111, splice @bytes, 0, 2);
        }
        elsif ($top == 4) {
            push @chars, utf8_char($byte & 0b0111, splice @bytes, 0, 3);
        }
        elsif ($top == 5) {
            push @chars, utf8_char($byte & 0b0011, splice @bytes, 0, 4);
        }
        elsif ($top == 6) {
            push @chars, utf8_char($byte & 0b0001, splice @bytes, 0, 5);
        }
        else {
            die "Malformed UTF-8; byte=$byte\n";
        }
    }
    return pack 'U*', @chars;
}
