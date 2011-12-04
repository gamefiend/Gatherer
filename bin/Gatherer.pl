#!/usr/bin/perl -w

use Modern::Perl;
use Cwd;
use File::Path;
use YAML;
use Net::Domain qw (hostname);
use Win32::TieRegistry( Delimiter=>"/", ArrayValues=>1 );
require 'Gatherer-Commands.pm';

my $config = YAML::LoadFile('../cfg/products.cfg');
my $base = YAML::LoadFile('../cfg/base.cfg');
my $productdir = getbase(\%{$base->{'Base'}});

#MAIN
say "Beginning Log Gathering.  Please allow a few minutes for information to be collected.";
getProductConfig($config, $productdir);
createFrame();
createIndex();


#subroutines
sub getbase{
    my $baseinfo = shift; 
    my $information;
    foreach my $key (keys %{$baseinfo}){
        my $path = $baseinfo->{$key}{'Uninstall'};
        if(exists $Registry->{$path}){
            $information->{$key}{'InstallLocation'} = $Registry->{$path}->GetValue('InstallLocation');
            $information->{$key}{'DisplayVersion'} = $Registry->{$path}->GetValue('DisplayVersion');
        }elsif(!(exists($Registry->{$path}))){
            $information->{$key}{'InstallLocation'} = '';
            $information->{$key}{'DisplayVersion'} = '';
        }
    }
    return $information;    
}

sub getProductConfig{
    my $yamlHash = shift;
    my $prodinfo = shift;
    my $key;
    foreach $key (keys (%{$yamlHash->{'Product'}})){
        my $curdir = getcwd;
        switchdir($key);
        my $switchdir = getcwd;
        foreach my $subkey(keys(%{$yamlHash->{'Product'}->{$key}})){
            if ($prodinfo->{$key}->{'InstallLocation'} eq ''){
                next;
            }
            given ($subkey){
                when ('Registry'){
                    regenum($yamlHash->{'Product'}->{$key}->{$subkey}->{'Keys'},
                            $yamlHash->{'Product'}->{$key}->{$subkey}->{'Filename'});
                }
                when ('WQL') {
                    displayWMI($yamlHash->{'Product'}->{$key}->{$subkey}->{'Filename'},
                               \%{$yamlHash->{'Product'}->{$key}->{$subkey}->{'WMI'}});
                }
                when ('FileVersion') {
                    getFileVersion($yamlHash->{'Product'}->{$key}->{$subkey}->{'Filename'},
                                   \%{$yamlHash->{'Product'}->{$key}->{$subkey}->{'Files'}},
                                   $prodinfo->{$key}->{'InstallLocation'});
                }
                when ('GrabFiles') {
                    pullFile(\%{$yamlHash->{'Product'}->{$key}->{$subkey}->{'Files'}},
                             $prodinfo->{$key}->{'InstallLocation'},
                            $switchdir);
                }
            }
        }
        resetdir($curdir);
    }   
}