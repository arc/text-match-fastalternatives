use ExtUtils::MakeMaker;
my $module_file = 'lib/Text/Match/FastAlternatives.pm';
WriteMakefile(
    NAME          => 'Text::Match::FastAlternatives',
    AUTHOR        => 'Aaron Crane <arc@cpan.org>',
    ABSTRACT_FROM => $module_file,
    VERSION_FROM  => $module_file,
    OBJECT        => 'FastAlternatives.o',
);
