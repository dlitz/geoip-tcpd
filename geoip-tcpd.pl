#!/usr/bin/perl -w
##############################################################################
# geoip-tcpd.pl - A tcpd-like wrapper for inetd that attempts to block
#                 incoming connections based on their country of origin.
# $Id$
##############################################################################
# Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
##############################################################################
#
# This is intended to work with the GeoLite Country database from
# <http://www.maxmind.com/>.
#
# This script doesn't do much.  It doesn't send anything to syslog, and it
# doesn't have POD documentation.
#
##############################################################################
#
# Example /etc/inetd.conf line:
#
#   ftp stream tcp nowait root  /path/to/geoip-tcpd.pl vsftpd /path/to/blacklist.txt /path/to/GeoIP.dat /usr/sbin/vsftpd
#
# Example /etc/inetd.conf line (if you want to run ordinary tcp-wrappers too):
#
#   ftp stream tcp nowait root  /usr/sbin/tcpd /path/to/geoip-tcpd.pl /path/to/blacklist.txt /path/to/GeoIP.dat /usr/sbin/vsftpd
#
##############################################################################

use strict;
use IO::File;
use Geo::IP;
use Socket;
use Socket6;    # Comment this out of you don't need IPv6 address support

sub die_usage
{
    die("Usage: $0 BLACKLIST GEOIP_DB program [args...]\n");
}

# Read the blacklist from the specified file.  Use two-letter country codes,
# one per line.  Blank lines are allowed, and comments are started using the
# hash ('#') character.
sub read_blacklist
{
    my $filename = $_[0];
    my $fh = new IO::File;
    my $blacklist = {};
    my $linenum = 0;
    $fh->open($filename, "r") or die("Couldn't open blacklist $filename");
    while (<$fh>) {
        $linenum++;
        chomp();
        s/^([^#]*)#.*$/$1/; # Strip commends
        s/^\s*//;           # Strip leading whitespace
        s/\s*$//;           # Strip trailing whitespace
        next if /^\s*$/;    # Skip empty lines
        /^\s*([A-Z]{2})\s*$/ or die("Syntax error on line $linenum of $filename.  Expected two-letter country code.\n");
        $blacklist->{$1} = 1;
    }
    $fh->close;
    return $blacklist;
}

# Check the specified IPv4 address against the blacklist.
sub check_blacklist
{
    my $v4addr = $_[0];         # dotted-quad IPv4 address
    our ($geoip, $blacklist);   # Global variables
    my $country_code = $geoip->country_code_by_addr($v4addr)
        or return;

    if (defined($blacklist->{$country_code})) {
        exit(2);    # Blacklisted
    }
}

my $blacklist_filename = shift @ARGV or die_usage;
my $geoip_database = shift @ARGV or die_usage;

# Read the country-code blacklist
our $blacklist = read_blacklist($blacklist_filename) or die("Couldn't read blacklist $blacklist_filename: $1\n");

# Open the GeoIP database
our $geoip = Geo::IP->open($geoip_database, GEOIP_STANDARD) or die("Couldn't open GeoIP database file $geoip_database: $1\n");

# Get the remote IPv4 or IPv6 address (the raw "struct sockaddr")
my $struct_sockaddr = getpeername(STDIN);
my ($port, $addr);

eval {
    # Try to decode IPv4 address
    ($port, $addr) = sockaddr_in($struct_sockaddr);
};
if ($@) {
    # Try to decode IPv6 address
    ($port, $addr) = sockaddr_in6($struct_sockaddr);
}

if (length($addr) == 4) {
    # IPv4 address
    my $hexaddr = unpack("H*", $addr);  # IPv6 address in hexadecimal
    $hexaddr =~ /^(..)(..)(..)(..)$/
        or die("BUG: IPv4 address not parseable"); # This should never happen
    check_blacklist sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));

} elsif (length($addr) == 16) {
    # The GeoIP library only supports IPv4 addresses, so try to decode
    # IPv4 addresses that might be encoded into an IPv6 address.
    # Note: This is not bulletproof, but no country-based IP blacklisting
    # mechanism is.

    my $hexaddr = unpack("H*", $addr);  # IPv6 address in hexadecimal
    if ($hexaddr =~ /^20010000(..)(..)(..)(..).*(..)(..)(..)(..)$/) {
        # Teredo (2001:0000::/32)
        # Check both the Teredo server and the NAT server
        check_blacklist sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));
        check_blacklist sprintf("%d.%d.%d.%d", 255^hex($1), 255^hex($2), 255^hex($3), 255^hex($4));

    } elsif ($hexaddr =~ /^0*ffff(..)(..)(..)(..)$/) {
        # IPv4 mapped address (::ffff:0.0.0.0/96)
        check_blacklist sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));

    } elsif ($hexaddr =~ /^0*([^0].)(..)(..)(..)$/) {
        # (Obsolete) IPv4-compatible address (::0.0.0.0/96)
        check_blacklist sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));

    } elsif ($hexaddr =~ /^2002(..)(..)(..)(..).*$/) {
        # 6to4
        check_blacklist sprintf("%d.%d.%d.%d", hex($1), hex($2), hex($3), hex($4));
    }
}

# No blacklist entry found.  Proceed to run the real program. (Passed in on the command-line).
exec @ARGV;
die("Couldn't exec $ARGV[0]: $!\n");

# vim:set ts=4 sw=4 sts=4 expandtab:
