#!/usr/bin/perl -w
#  version 2.0. - 2018.11.13
#  Sample External Authenticaton program for CommuniGate Pro 
#  that employs LDAP "bind", supports the account creation
#  via NEW command. 
#  A special edition for Microsoft ActiveDirectory LDAP server.
#  Revision 18.01.2018
#
#  See for more info:
#  <http://www.stalker.com/CommuniGatePro/Security.html#External>
#
#  Please mail your comments to <support@communigate.com>


use lib "/root/perl5/lib/perl5/" ;
#  You may need to install the following modules:
#  ASN1 from <http://www.cpan.org/modules/by-module/Convert/>
#  LDAP from <http://www.cpan.org/modules/by-module/Net/>
use Net::LDAPS;
use strict;
use threads;
use threads::shared;
use Thread::Queue; 
use MIME::Base64;

#  Take the CLI.pm module from <http://www.stalker.com/CGPerl/>
use CLI;

# added by haelkar-----------------------------------------
use Config::Simple;
my %cfg;
#Config::Simple->import_from('/2/ldap/cgp2.cfg', \%cfg) ||die Config::Simple->error(); # battle
Config::Simple->import_from('/home/haelkar/cgp2-test.cfg', \%cfg) || die Config::Simple->error();    # training
# -------------------------------------------------------------------
# You should redefine these values
#

my %domains=( # e-mail domains
    $cfg{'CGP.domain'}  => { # need to create this for every domain you use with external authentication
    address=>$cfg{'AD.server'},  #the URI or address of LDAP server
    backupAddress=>$cfg{'AD.server_backup'},  # backup LDAP server address (optional)
    timeout=>5, # timeout in seconds, 20 by default
    adminDN=>$cfg{'AD.admin'},     # the DN for admin bind
    adminPassword=>$cfg{'AD.pass'},

    searchBase=>$cfg{'AD.base'},                                             
    searchFilter=>'(&(sAMAccountName=<user>)(objectclass=*))',
    updatePasswords=>0,  #if need to update CommuniGate internal password
  },
  #'new.company.com' => {
  #  address=>'127.0.0.1',  
  #  adminDN=>'CN=Administrator,CN=Users,DC=new,DC=company,DC=com', 
  #  adminPassword=>'password',
  #
  #  searchBase=>'CN=Users,DC=new,DC=company,DC=com',                                             
  #  searchFilter=>'(&(mail=<user>@<domain>)(objectclass=user))',
  #  updatePasswords=>0,
  #},
);

my %attributes=(
 cn => 'RealName',
 userPassword => 'Password',
 o => 'Organization',
 ou => 'ou',
 st => 'st',
 l => 'l',
 sn => 'sn',
 givenName => 'givenName',
 title => 'title',
 telephoneNumber => 'telephoneNumber',
 mobile => 'mobile',
);

my $CGServerAddress = $cfg{'CGP.srv'};   # You should redefine these values
my $CLILogin = $cfg{'CGP.usr'};
my $CLIPassword = $cfg{'CGP.pwd'};
my $cacheTimeout=60*10; # in seconds
my $nThreads=5;	 

#
# END of user customiseable parameters 
#


$| = 1;     #force STDOUT autoflush after each write

print "* authLDAPNewAD.pl started\n";

my %passwordCache:shared;
my $mainQueue = Thread::Queue->new();


foreach my $i (1..$nThreads) {
  my $thr = threads->create(\&threadProc, "thread#$i" );
}

    
while(<STDIN>) {
  chomp;    # remove \n from the end of line
  my ($prefix,$method,@eargs) = split(/ /);

  if($method eq 'VRFY') {
    unless($prefix && $method && $eargs[0] && $eargs[1]) {  
      print "$prefix ERROR Expected: nnn VRFY (mode) user\@domain password\n";    
    } else {
      if($eargs[0] =~ /^\(.*\)$/) {
        shift @eargs;  
      }
      vrfy_command($prefix,$eargs[0],$eargs[1]);   
    }    
  } elsif($method =~ /^SASL/) {
     print "$prefix ERROR not supported\n";
  } elsif($method =~ /^READPLAIN/) {
     print "$prefix FAILURE not supported\n";
        
  } elsif($method eq 'NEW') {
    unless($prefix && $method && $eargs[0]) {  
      print "$prefix ERROR Expected: nnn NEW user\@domain\n";    
    } else {
      new_command($prefix,$eargs[0]);
    }
  } elsif($method eq 'INTF') {
    print "$prefix INTF 7\n";

  } elsif($method eq 'QUIT') {
    print "$prefix OK\n";
    last;
  } else {
    print "$prefix ERROR Only INTF, VRFY, and NEW commands supported\n";    
  }   
}

foreach (1..$nThreads) {
    $mainQueue->enqueue(undef);
}    
foreach my $thr (threads->list()) {
  $thr->join();
}
 
print "* authLDAPNewAD.pl done\n";
exit(0);


sub tryConnectServer {
  my ($thrName,$domain)=@_;
  my $domData=$domains{$domain};
  my $adr=$domData->{address};

  if($domData->{backupSwitchTime}) {
    if($domData->{backupSwitchTime}+60 > time() ) { #use backup for 60 seconds 
      $adr=$domData->{backupAddress};
    } else {
      delete $domData->{backupSwitchTime};
    }
  }
  print "* ($thrName) trying to connect to $adr\n";
  
  my $ldap = Net::LDAPS->new($adr,timeout=>($domData->{timeout} || 20),inet4=>1,inet6=>0 );
  unless($ldap) {
    if($domData->{backupAddress}) {
      print "* ($thrName) connection failed, trying backup at $domData->{backupAddress}\n";
      $ldap = Net::LDAPS->new($domData->{backupAddress},timeout=>($domData->{timeout} || 20),inet4=>1,inet6=>0 );
      $domData->{backupSwitchTime}=time() if($ldap); 
    }
  }  
  return $ldap;
}


sub vrfy_command {
  my ($prefix,$user,$password)=@_;

  my ($name,$domain)=("",""); 
  if($user =~ /(.+)\@(.+)/) {  
    $name=$1;
    $domain=$2;
  } else {
    print "$prefix ERROR Full account name with \@ and domain part expected\n";
    return;
  }

  if($passwordCache{"$user/p"}) {
    if($passwordCache{"$user/t"} + $cacheTimeout > time() && $passwordCache{"$user/p"} eq $password) {
      print "* user $user found in cache\n";
      print "$prefix OK\n";
      return;
    } else {
      delete $passwordCache{"$user/p"};
      delete $passwordCache{"$user/t"};
    }
  }
  unless($domains{$domain}) {
    print "$prefix ERROR the domain '$domain' is not served, check settings.\n";
    return;
  }
  $mainQueue->enqueue(['VRFY',$prefix,$user,$password,$name,$domain]);
} 

sub vrfy_thread {
  my ($thrName,$prefix,$user,$password,$name,$domain)=@_;   
  my $ldap = tryConnectServer($thrName,$domain);
  unless($ldap) {
    return "Failed to connect to LDAP server";
  }
  
  my $adminDN=$domains{$domain}->{adminDN};
  my $adminPassword=$domains{$domain}->{adminPassword};
 
  my $result;
  $result=$ldap->bind($adminDN,password=>$adminPassword)
    || return "Can't bind as admin: ".$result->error;
  $result->code && return "Can't bind as admin: ".$result->error;

  my $searchBase=$domains{$domain}->{searchBase};
  $searchBase=~s/<user>/$name/g;
  $searchBase=~s/<domain>/$domain/g;
  my $searchFilter=$domains{$domain}->{searchFilter};
  $searchFilter=~s/<user>/$name/g;
  $searchFilter=~s/<domain>/$domain/g;
  print "* ($thrName) searching $searchBase for $searchFilter\n";
 
  my $mesg = $ldap->search (  # perform a search
               base   => $searchBase,
               filter => $searchFilter
             );


#  $ldap->unbind();                        # unbind & disconnect

  unless(defined $mesg) {
    return "LDAP search failed";   
  } 
  if($mesg->all_entries() eq 0) {
    return "LDAP: nothing found for $searchFilter";
  }
 
  my ($bindDN);  
  foreach my $entry ($mesg->all_entries) {
    #my $ref1=@$entry{'asn'};
    $bindDN=@$entry{'asn'}->{'objectName'};
    last; # we need only 1 entry
  }

  #----added by <haelkar>----------------------------
  #Checking Membership
  my @memberOf=$mesg->entry(0)->get_value('memberOf');
  my $group = 'cgp-mail';
  unless((grep {m/$group/} @memberOf)){ return "User has insufficient rights!" } ;
  #-------------------------------------------------------------

  $password=decodeString($password);
  print "* ($thrName) binding $bindDN with password=$password\n";
  $result=$ldap->bind($bindDN,password=>$password)
    || return "Can't bind: ".$result->error;

  $ldap->unbind();                        # unbind & disconnect
  #$ldap->disconnect();
  
  $result->code && return $result->error; # return error message if failed

  $passwordCache{"$user/t"}=time();

  $passwordCache{"$user/p"}=$password; 

  print "$prefix OK\n";

  if($domains{$domain}->{updatePasswords}) {
    my $cli = new CGP::CLI( { PeerAddr => $CGServerAddress,
                            PeerPort => 106,
                            login    => $CLILogin,
                            password => $CLIPassword
                          } );
    unless($cli) {  
     print "* Can't login to CGPro via CLI: ".$CGP::ERR_STRING."\n";
     return undef;
    }
    unless($cli->SetAccountPassword($user,$password)) {
      print "* Can't set password:".$cli->getErrMessage."\n";
    }
    $cli->Logout();
  }
  return undef;                           # return "undef" on success
}




sub new_command { # changed completely by haelkar
  my ($prefix,$user)=@_;

  my ($name,$domain)=("",""); 
  if($user =~ /(.+)\@(.+)/) {  
    $name=$1;
    $domain=$2;
  } else {
    print "$prefix ERROR Full account name with \@ and domain part expected\n";
    return;
  }
  unless($domains{$domain}) {
    print "$prefix ERROR the domain '$domain' is not served, check settings.\n";
    return;
  }

  $mainQueue->enqueue(['NEW',$prefix,$user,$name,$domain]);
}   

sub new_thread { my ($thrName,$prefix,$user,$name,$domain)=@_;
  #----added by <haelkar>---------------------------------------
  #Checking AD-account
  return "Invalid account!" unless $name =~m/^st\d{6}$/;
  #-------------------------------------------------------------
  my $ldap = tryConnectServer($thrName,$domain);
  unless($ldap) {
    return "Failed to connect to LDAP server";
  }
  
  my $adminDN=$domains{$domain}->{adminDN};
  my $adminPassword=$domains{$domain}->{adminPassword};
 
  my $result;
  $result=$ldap->bind($adminDN,password=>$adminPassword)
    || return "Can't bind as admin: ".$result->error;
  $result->code && return "Can't bind as admin: ".$result->error;

  my $searchBase=$domains{$domain}->{searchBase};
  $searchBase=~s/<user>/$name/g;
  $searchBase=~s/<domain>/$domain/g;
  my $searchFilter=$domains{$domain}->{searchFilter}; # "(&(sAMAccountName=$name)(MemberOf=CN=cgp-mail,OU=MAIL,OU=Группы,DC=ad,DC=pu,DC=ru) (objectclass=*))"
  $searchFilter=~s/<user>/$name/g;
  $searchFilter=~s/<domain>/$domain/g;
  print "* ($thrName) searching $searchBase for $searchFilter\n";
 
  my $mesg = $ldap->search (  # perform a search
               base   => $searchBase,
               filter => $searchFilter
             );


  $ldap->unbind();                        # unbind & disconnect

  unless(defined $mesg) {
    return "LDAP search failed";   
  } 
  if($mesg->all_entries() eq 0) {
    return "LDAP: nothing found for $searchFilter";
  }
  my ($realName,$password);  
  foreach my $entry ($mesg->all_entries) {
    my $ref1=@$entry{'asn'};
    my $attrs=@$ref1{'attributes'};
    foreach my $atrRef (@$attrs) {
      my $type=@$atrRef{'type'};
      my $vals=@$atrRef{'vals'};
      $realName=@$vals[0] if($type eq 'cn');
      $password=@$vals[0] if($type eq 'userPassword');
    }

  #Checking Membership
  my @memberOf=$mesg->entry(0)->get_value('memberOf');
  my $group = 'cgp-mail';
  unless((grep {m/$group/} @memberOf)){ return "User has insufficient rights!" } ;
  #-------------------------------------------------------------
  
    last; # we need only 1 entry
  }
  my %userData;
   $userData{'RealName'}=$mesg->entry(0)->get_value('DisplayName');#$realName if(defined $realName);
  $userData {'ou'}=($mesg->entry(0)->get_value('department'));
  $userData {'ou'}=~ s/\"/\\"/g;
	$userData {'title'}=($mesg->entry(0)->get_value('title'));
	$userData {'company'}=($mesg->entry(0)->get_value('company'));
  $userData {'company'}=~ s/\"/\\"/g;
	$userData {'telephoneNumber'}= ($mesg->entry(0)->get_value('telephoneNumber'));
  $userData {'mail'}= ($mesg->entry(0)->get_value('mail'));
  #$userData{'Password'}=$password if(defined $password); 
  my $Translit = $mesg->entry(0)->get_value('displayNamePrintable') || '';
  my $aliases1 = ($mesg->entry(0)->get_value('otherMailbox',asref=>1));

  my $dn;
  my $Fullname = $userData{'RealName'};
  if ($Translit ne "") { $dn = $Translit } else {$dn = $Fullname}
  print "* ($thrName) found $realName\n" if(defined $realName);

  #----added by <haelkar>---------------------------------------
  # fields for web-user
    my @froms;
    my @alias_all;
    my %webSettings;
    #my $Fullname = $mesg->entry(0)->get_value('DisplayName');
    my $Nacc = $mesg->entry(0)->get_value('mail');
    $webSettings{UserFrom} = '\"'.$dn.'\" <'.$Nacc.'>';
    #undef @alias_all; 
    my $mail = ($mesg->entry(0)->get_value('mail'));
                $mail =~ /(.+)\@(.+)/; # spit "@***.**"
                if ($2 eq 'spbu.ru'){
                push  @alias_all,$1};

              my $al;
              foreach $al (@$aliases1){
                  $al =~ /(.+)\@(.+)/;
		  if ($2 eq 'spbu.ru'){
        push @alias_all,$1;
        my $string = '\"'.$userData{'RealName'}.'\" <'.$1.'@spbu.ru>';
        push @froms, $string;
        };
               };
    $webSettings{UserFroms} =   [@froms];       
      
  # back to business
  my $cli = new CGP::CLI( { PeerAddr => $CGServerAddress,
                          PeerPort => 106,
                          login    => $CLILogin,
                          password => $CLIPassword
                        } )  
  || return "Can't login to CGPro via CLI: ".$CGP::ERR_STRING;
  $cli->CreateAccount(accountName=>"$user",settings=>\%userData) || return "Can't create account via CLI:".$cli->getErrMessage;
  $cli->SetAccountAliases("$user",[@alias_all]) || return "Can't create alias ".$cli->getErrMessage." "."@alias_all" ;
  $cli->SetWebUser("$user", {%webSettings} ) || return "Can't set Web settings for $user:" . $cli->getErrMessage;
  $cli->Logout();
  print "$prefix OK\n";
  return undef;
}

sub threadProc {
  my ($name)=@_;
  print "* $name started\n";
  while (my $data = $mainQueue->dequeue()) {
    my $errorMsg;
    if($data->[0] eq 'VRFY') {
      $errorMsg=vrfy_thread($name,$data->[1],$data->[2],$data->[3],$data->[4],$data->[5]);
    }elsif($data->[0] eq 'NEW') {
      $errorMsg=new_thread($name,$data->[1],$data->[2],$data->[3],$data->[4]);
    }else{
      print "* $name unknown command $data->[0]\n";
    }

    if(defined $errorMsg) {
      print "$data->[1] ERROR ($name) $errorMsg\n";
    }      

  }
  print "* $name quitting\n";
}
 

sub decodeString {
  my ($data)=@_;
  my $isQuoted=0;

  unless($data=~/^\"(.*)\"$/) { # check "'s
    return $data;
  }
  $data=$1;

  my $result="";
  my $span=0;
  my $len=length($data);

  while($span < $len) {
    my $ch=substr($data,$span,1);
    if($ch eq '\\') {
      $span++;
      if(substr($data,$span,3) =~ /^(\d\d\d)/) { 
        $ch=chr($1); $span+=3;
      }else {
        $ch=substr($data,$span,1);
      }  
    }
    $result .= $ch;
    ++$span;
  }
  return $result;
}


__END__

