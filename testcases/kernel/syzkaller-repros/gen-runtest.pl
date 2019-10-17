#!/usr/bin/env perl

use 5.012;
use strict;
use warnings;
use Getopt::Long;

my $help = 0;
my $build_dir;
my $sut_dir;
my $out_dir = './';
my $batch_size = 0xffff;

GetOptions('help' => \$help,
           'build-dir=s' => \$build_dir,
           'sut-dir=s' => \$sut_dir,
           'out-dir=s' => \$out_dir,
           'batch-size=i' => \$batch_size) || die("Error parsing arguments: $!");

my $help_msg = <<'EOS';
gen-runtest.pl --help

The switch '--help' produces this message.

gen-runtest.pl --build-dir=<path> [--sut-dir=<path>] [--out-dir=<path>] [--batch-size=<int>]

This script will read the executable file names in a directory and write them
into a series of one or more runtest files. The file names may only contain
the letters and numbers in the ranges a-z and 0-9, other files will be ignored.

    --build-dir:  The directory where the reproducer executables are currently available.
    --sut-dir:    The directory where the reproducers will be availabe on the SUT. Defaults 
                  to the build-dir.
    --out-dir:    Where to put the runtest files. Defaults to './'.
    --batch-size: How many reproducers to put in each runtest file, defaults to 0xffff.

The runtest files will have names like 'syzkallerN' where N is the batch number.

EOS

if ($help) {
    print($help_msg);
    exit 0;
}

!$build_dir && die("Missing required --build-dir parameter!\n\n$help_msg");

$sut_dir //= $build_dir;

opendir(my $dir, $build_dir) || die("Could not open $build_dir: $!");

my @exes = grep { /^[a-z0-9]+$/ } readdir($dir);
my $len = scalar @exes;

close($dir);

print "Found $len reproducers in $build_dir\n";

my $count = 0;
my $batch = 0;
my $out = 0;

for my $exe (@exes) {
    $count++;

    if ($count > $batch * $batch_size) {
        $batch++;

        $out && close($out);
        my $batch_file = "$out_dir/syzkaller$batch";
        open(my $fh, '+>', $batch_file) || die("Could not open $batch_file: $!");
        $out = $fh;
        print "Creating runtest file $batch_file\n";
    }

    print $out "$exe syzwrap -d $sut_dir -n $exe\n";
}

