#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Std;
use File::Find;
use Cwd;

use vars qw($opt_h $opt_d);
getopts('hd');

my @test_files;
my $test_mod;
my $test_dir = 'test';
#my $std_out_file = "test.log";
my $curr_dir = getcwd();
my $test_cmd = $curr_dir."/"."$test_dir/ssl_test";
my $ca = $curr_dir."/"."$test_dir/pem/cacert.pem";
my $key = $curr_dir."/"."$test_dir/pem/privkey.pem";
my $port = 445;
my $cmd_param = "cmd_param";
my $test_info = "test_info";
my $cmd_str;

my @testcase = (
    {
        $cmd_param => "-c $ca -k $key -p $port",
        $test_info => "DoveSSL--->DoveSSL OK!",
    },
    {
        $cmd_param => "-c $ca -k $key -p $port -C",
        $test_info => "OpenSSL--->DoveSSL OK!",
    },
    {
        $cmd_param => "-c $ca -k $key -p $port -S",
        $test_info => "DoveSSL--->OpenSSL OK!",
    },
    {
        $cmd_param => "-c $ca -k $key -p $port -C -S",
        $test_info => "OpenSSL--->OpenSSL OK!",
    },
);

sub usage {
    print ("usage: $0 ");
    print ("\t\t\t\t-d (no args, debug mode)\n");
    print ("\t\t\t\t-h (no args, help)\n");
}

for my $tc (@testcase) {
    $cmd_str = "sudo $test_cmd $tc->{$cmd_param}";
    if (!$opt_d) {
        $cmd_str .= " 1>/dev/null";
    }
    my $ret = system($cmd_str);
    $ret /= 256;
    if ($ret eq 0) {
        print("testcase $tc->{$test_info} succeed!\n");
    } else {
        print("testcase $tc->{$test_info} failed! ret = $ret\n");
    }
}


