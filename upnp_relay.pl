#!/usr/bin/perl

# upnp_relay.pl version 1.0
# $Id: upnp_relay.pl 24 2009-01-30 05:05:02Z nandor $

##############################################
# Authors:
#         Garrett Scott    garrett@gothik.org
#         Nandor T. Szots  nandor@szots.com 
##############################################

use strict;
use IO::Socket::Multicast;
use IO::Socket;
use Net::RawIP;
use Getopt::Std;
use Net::Ifconfig::Wrapper qw( Ifconfig );


my %opts;
getopts('d:l:r:p:e:h:f', \%opts);

if( defined($opts{'h'}) ||
   !defined($opts{'r'}) )
{
    print "$0: command line arguments\n";
    print "-h              this help\n";
    print "-r remote_host  (required) remote host to connect to\n";
    print "-p remote_port  remote port\n";
    print "-l local_port   local port to listen for connections on (default: 1313)\n";
    print "-e eth device   network device to listen for multicast packets on\n";
    print "-d debug        debug level 1-<n>\n";
    print "-f force        force run (ignore root warnings)\n";
    exit;
}

my $debug        = $opts{'d'};
my $remote_host  = $opts{'r'};
my $remote_port  = $opts{'p'};
my $local_port   = $opts{'l'};
my $local_eth    = $opts{'e'};
my $force        = $opts{'f'};

my $local_ip;
my $network;
my $netmask;

unless($force) {
	die "You need to run this script as root to construct relay packets\n" if $>;
} {
	_debug("Ignoring non-privledged user check.  Good luck!\n");
}

if( !defined( $local_eth ) )
{
    my $s = IO::Socket::INET->new(Proto => 'udp') or die "Unable to detect local network\n";;
    print "Detecting network...\n";
    ( $local_ip, $network, $netmask ) = &get_network();

    die "Unable to detect network info!" unless( defined( $netmask ) and defined( $local_ip ) and defined( $network ) );

    $local_eth = $s->addr_to_interface( inet_ntoa( $local_ip ) );
}
else
{
    my $s = IO::Socket::INET->new(Proto => 'udp') or die "Unable to detect local network\n";;

    $local_ip = inet_aton( $s->if_addr( $local_eth ) );
    $netmask  = inet_aton( $s->if_netmask( $local_eth ) );

    die "Unable to determine network info for: $local_eth!" unless( defined( $netmask ) and defined( $local_ip ) );

    $network  = $local_ip & $netmask;
}

if( !defined( $remote_port ) )
{
    $remote_port = "1313";
}

if( !defined( $local_port ) )
{
    $local_port = "1313";
}

my $local_addr   = inet_ntoa( $local_ip );
my $network_addr = inet_ntoa( $network );
my $netmask_addr = inet_ntoa( $netmask );

print "Using local network: $local_addr:$netmask_addr on $local_eth (If this is incorrect kill this script now to avoid broadcast storms)\n";

$SIG{__DIE__} = \&DIE_handler;
$SIG{CHLD}    = \&CHLD_handler;
$SIG{ABRT}    = \&ABRT_handler;

print "Forking...\n";
my $pid = fork();

die "Unable to fork()!\n" if( not defined $pid );

my $remote_connection;

if( $pid == 0 )
{
    # Child
    my $tcp_listener = new IO::Socket::INET (
                        LocalHost => $local_addr,
                        LocalPort => $local_port,
                        Proto => 'tcp',
                        Listen => 1,
                        Reuse => 1 ) or die "Could not create socket: $!\n";

    while( 1 )
    {
        my $client = $tcp_listener->accept();

        ( my $port, my $ipaddr ) = sockaddr_in( $client->peername );
        my $host = inet_ntoa( $ipaddr );
        print "Connection fron Client $host/$port\n";

        my $line;
        my $cur_host;
        my $cur_port;
        my $spoof_host;
        my $spoof_port;

        while(<$client>)
        {
            my $c_line = $_;
            if( $c_line =~ /PACKETFROM: (.*)\r\n/ )
            {
                ( $spoof_host, $spoof_port ) = split(/:/, $1);
                print "New Host: $spoof_host:$spoof_port\n" if( $debug >= 1 );
            }
            else
            {
                $line  .= $c_line;
            }

            if( $c_line =~ /^\r\n$/ )
            {
                # packet end
                print "\nGot complete packet sending...\n" if( $debug >= 1 );
                print "[\n\n$line]\n" if( $debug >= 2 );

                my $dest = "239.255.255.250";

                my $spoof_sock = new Net::RawIP({udp =>{}});

                $spoof_sock->set( {ip => {saddr => $spoof_host,
                                          daddr => $dest,
                                          tos => 22} ,
                                   udp  => {source => $spoof_port,
                                            dest => 1900,
                                            data => $line } } );
                $spoof_sock->send;

                $line = "";
            }
        }
        print "Connection lost...\n\n";
        kill 6, $pid;    
    }
}
else
{
    # Parent

    my $mcast_listener = IO::Socket::Multicast->new(LocalPort=>1900, Reuse=>1) or die "$!\n";

    &connect();

    # Add a multicast group
    $mcast_listener->mcast_add( '239.255.255.250', $local_eth );

    while( 1 )
    {
        # now receive some multicast data
        $mcast_listener->recv(my $mcast_data, 4096);
        next if( !$mcast_listener->peername );
        (my $from_port, my $from_host) = sockaddr_in( $mcast_listener->peername );
        my $from_addr = inet_ntoa( $from_host );

        print "DATA from $from_addr\n" if( $debug >= 1 );

        # don't re-multicast data that didn't originate on our network or
        # doesn't give information about our network...

        my $location = $mcast_data;
        my $location_addr;

        if( $location =~ /LOCATION:/i )
        {
            $location =~ s/\s//g;
            $location =~ tr/[A-Z]/[a-z]/;
            $location =~ s/.*location:http:\/\///g;
            $location =~ s/:.*//g;
            $location_addr = inet_aton( $location );
        }
        else
        {
            $location = "";
            $location_addr = inet_aton( "0.0.0.0" );
        }

        print "Packet Location: $location\n" if( $location && $debug >= 1 );

	my $loc = "Unknown";
	   $loc = inet_ntoa( $location_addr & $netmask ) if( $location_addr );

        print "Location: $loc Host: " . inet_ntoa( $from_host & $netmask ) . "\n" if( $debug >= 1 );

        # using the network host here doesnt work for == not sure why...
        unless( ( $loc eq $network_addr ) ||
                ( inet_ntoa( $from_host     & $netmask ) eq $network_addr ) )
        {
            $mcast_data =~ s/\r\n/ /g;
            print "Tossing: " . $mcast_data . "\n\n" if( $debug >= 2 );
            next;
        }
        print "Client said:\n$mcast_data\n" if( $debug >= 2 );

        if( $remote_connection && $remote_connection->peername )
        {
            $remote_connection->send( "PACKETFROM: $from_addr:$from_port\r\n" ) or _debug( "send() failed on the packet line\n" );
            $remote_connection->send( $mcast_data ) or _debug( "send() failed on the data line\n" );
        }
        else
        {
            &connect();
        }
    }

    waitpid( $pid, 0 );
}

sub get_network
{
        my @addrs;
        my $rh = Ifconfig('list', '', '', '');
        foreach my $interface (keys %$rh) {
            if ($interface =~ /^e/i) { #TODO: Ugly hack to prefer ethernet - find a better way
                _debug("found potential interface $interface\n");
            } else {
                _debug("skipping interface $interface auto-detect.  If this is the inteface you want, please specify it on the command line with \'-e $interface\'\n");
                next;
            }
            if ($rh->{$interface}->{inet}) {
                _debug("found potential interface $interface\n");
            } else {
                _debug("skipping auto-detect - no bound ipv4 addresses\n");
                next;
            }
            foreach my $addy (keys %{$rh->{$interface}->{inet}}) {
                push @addrs, $addy . "/" . $rh->{$interface}->{inet}->{$addy};
            }
        }

        foreach (@addrs)
        {
            next unless( /\d+\.\d+\.\d+\.\d+/ );
            ( my $net, my $mask ) = split( /\// );
            my $nn = inet_aton( $net );
            my $mn = inet_aton( $mask );
            return ( $nn, $nn & $mn, $mn )
        }
}

sub connect
{
    print "Attempting connection to: $remote_host:$remote_port\n";

    while( 1 )
    {
        $remote_connection = IO::Socket::INET->new( Proto => 'tcp',
                                   PeerAddr => $remote_host,
                                   PeerPort => $remote_port );
        if( !defined( $remote_connection ) )
        { 
            print "Connection to relay server failed: $!, retrying in 5 seconds...\n";
            sleep 5;
        }
        else
        {
            last;
        }
    }
    $remote_connection->autoflush(1);
    print "Connected to remote relay host!\n";
}

sub _debug {
    return if ! $debug;
    print STDERR "Debug $$: ";
    print STDERR @_;
} # _debug

sub ABRT_handler
{
    if( $pid > 0 )
    {
        $remote_connection->close();
        &connect();
    }
}

sub CHLD_handler
{
    $SIG{CHLD} = \&CHLD_handler;
    my $pid = wait;
    die "My child died so I am dying too!\n";
}

sub DIE_handler
{
    return 1 if( $pid == 0 );
    kill 9, $pid;
    return 1;
};
