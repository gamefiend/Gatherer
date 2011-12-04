use Modern::Perl;
use POSIX qw(strftime);
use Win32::TieRegistry( Delimiter=>"/", ArrayValues=>1 );
use Win32::NetAdmin qw (LocalGroupGetMembers);
use Data::Dumper;
use DBD::WMI;
use Win32::OLE;
use Cwd;
use Win32::EventLog;
use Net::Domain qw (hostname);


#Registry Functions
sub regenum{
    my $regkeys = shift;
    my $hrefFilename = shift;
    my $curdir= cwd;
    open(REG,">$hrefFilename") or die "cannot create file $hrefFilename : $! \n";
    select(REG);
    make_html_open();
    foreach my $key (keys %{$regkeys}){
        make_header($key, "h2");
        walkreg($regkeys->{$key});
        }
    make_html_close();
        handleswitch('REG');
}

sub walkreg{
    my $hive = shift;
    if (defined ($Registry->{$hive})){
        my @test = $Registry->{$hive}->MemberNames();    
        if (exists $Registry->{$hive}){
            foreach my $value (@test){
                given ($value){
                    when (/^\//){
                    $Registry->ArrayValues(1);
                    my ($valuedata, $valuetype) = $Registry->{$hive}->{$value};
                            say "<p>$value\t@{$valuedata}[0]<p>";
                    }
                    when (/\/$/){
                    my $combined = $hive . "\/" . $value;
                        if (exists ($Registry->{$combined})){
                            make_header($combined, "h3");
                            walkreg($combined);
                        }
                    }
                }
            }
        }
    }

}

#WMI Functions
sub displayWMI {
    my $hrefFilename = shift;
    my $hrefWMI = shift;
    my @disp;
    my $wmi = getWMI($hrefWMI->{'WSQL'});    
    open(WMI,">$hrefFilename") or die "cannot create file $hrefFilename : $! \n";
    select(WMI);
    make_html_open();

    make_table();
    make_table_header($hrefWMI->{'FIELDS'});
    while(my @row = $wmi->fetchrow){
        my $display = $row[0];
        foreach(@{$hrefWMI->{'FIELDS'}}){
        push @disp,$display->{$_};
        }
    make_row(\@disp);
    }
    make_table_close();
    make_html_close();
    handleswitch('WMI');
}

sub getWMI{
    my $wql = shift;
    my $dbh = DBI->connect('dbi:WMI:') or die "Cannot connect to WMI database : $! \n";
    my $sth=$dbh->prepare($wql) || die "can't execute statement : $! \n";
    $sth->execute();
    return $sth;
}


sub get32or64{
    my $wmi = getWMI('select * from Win32_Processor where DeviceID="CPU0"');    
    while(my @row = $wmi->fetchrow){
        my $display = $row[0];
        return $display->{'AddressWidth'};
        }
}


sub getFileVersion{
    my $hrefFilename = shift;
    my $file = shift;
    my $base = shift;
    open(FILE,">$hrefFilename") or die "cannot create file $hrefFilename : $! \n";
    select(FILE);    
    make_html_open();
    my $_app_object = (Win32::OLE->GetActiveObject('WScript.Shell') || Win32::OLE->new('WScript.Shell'));
    my $objFSO = Win32::OLE->new('Scripting.FileSystemObject');
    make_table();
    foreach my $key (sort (keys %{$file})){
        my $path = "$base". "\\"."$file->{$key}";
        if (-f $path){
           my $fileversion = $objFSO->GetFileVersion($path);
           make_row(["$key version",$fileversion,$path]);
            }
        else{
            make_row(["$key version", "Not Present",$path]);
        }
    }
    make_table_close();
    make_html_close();
    handleswitch('FILE');
}

# EventViewer Functions
sub getEVT{
    my $hrefFilename = shift;
    my $EVT = shift;
    my %type = (1 => "ERROR", 
    2 => "WARNING", 
    4 => "INFORMATION", 
    8 => "AUDIT_SUCCESS", 
    16 => "AUDIT_FAILURE"); 
    
    my $entry;
    my $count=100;
    my $i=0;
    
    # if this is set, we also retrieve the full text of every 
    # message on each Read( ) 
    $Win32::EventLog::GetMessageText = 1; 
    
    # open the Application event log 
    my $log = new Win32::EventLog("$EVT", $ENV{ComputerName}) 
        or die "Unable to open system log:$^En"; 

    open(EVT,">$hrefFilename") or die "cannot create file $hrefFilename : $! \n";
    select(EVT);    
    # read through it one record at a time, starting with the first entry
    make_html_open();
    make_table();
    make_table_header(['Time','Event ID','Source','Event Type','Message']);
    while ($log->Read((EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ),2,$entry) && $i < $count){
        if (defined($entry)){
            my $evt = ($entry->{EventID} & 0xffff);
            my $time = POSIX::strftime("%m/%d/%Y %H:%M:%S", localtime($entry->{TimeGenerated}));
            make_row([$time,$evt,$entry->{Source},$type{$entry->{EventType}},$entry->{Message}]);
            $i++;
        }
    }
    make_table_close();
    make_html_close();
    handleswitch('EVT');
}



sub GetEventLogs{
    my $path = "..\\info\\system";
    $path = Cwd::fast_abs_path($path);
    say "Gathering Event Logs (EVT format)";
    say "$path";
    system("cscript eventlog.vbs \"$path\"");
}
sub GetRSOP{
    say "Gathering RSOP Information";
    system('gpresult.exe /H ..\info\system\RSOP.html');
}

sub GetAdminGroup{
    my $group = "Administrators";
    my $user = getlogin();
    my @groups;
    my $filename = "..\\info\\system\\GroupAdmin.txt";
    LocalGroupGetMembers('',$group, \@groups);
    open(ADM, ">$filename") or die "cannot open file $! \n";
    select(ADM);
    say "USERS IN LOCAL ADMINISTRATORS GROUP (WILL NOT APPLY ON DCs)";
    foreach my $member (@groups){
        given ($member){
            when(/$user/i){
                say "$member : Logged On";
            }
            default{
                say "$member";
            }
        }
    }
    handleswitch('ADM');
}

sub GetFireWallInfo{
    my $display;
    my @disp;
    my $wmiFW = {
        WSQL => 'SELECT * FROM Win32_Service Where Name="MpsSvc" ',
        FIELDS => ['Name','Started']
        };
    say "Gathering Firewall Policy Information";
    my $query = getWMI($wmiFW->{'WSQL'});
    say $wmiFW->{'WSQL'};
    while(my @row = $query->fetchrow){
        $display = $row[0];
        }
    given($display->{'Started'}){
        when(1){
            say "Firewall is enabled, getting rules.";
            system('netsh advfirewall show allprofiles > ..\info\system\FireWall.txt');
        }
        default{
            open(FW,">>..\\info\\system\\FireWall.txt") or die "can't open file. $! \n";
            select(FW);
            say "Firewall Service is not enabled, so rules cannot be accessed.";
            handleswitch('FW');
        }
    }
}

sub getSysInfo {
    my %sysdata = (
        MDAC => '/LMachine/Software/Microsoft/DataAccess/'
    );
    my $curdir = getcwd;
    #run executables and scripts
    switchdir('system');
    resetdir($curdir);
    execdir();
    GetEventLogs();
    GetRSOP();
    GetAdminGroup();
    GetFireWallInfo();
    
    # General System Info.
    switchdir('system');
    system('%comspec% /cwmic /output: Services.html SERVICE GET Caption,Name,Description,DesktopInteract,PathName,Started,Startname,State /FORMAT:htable');
    system('%comspec% /c Systeminfo  > Sysinfo.txt');
    system('%comspec% /c Tasklist /V  > tasklist.txt');
    system('%comspec% /c COPY %WINDIR%\System32\drivers\etc\hosts Net_hosts.txt /Y');
    system('%comspec% /c COPY %WINDIR%\System32\drivers\etc\lmhosts Net_lmhosts.txt /Y');
    system('%comspec% /c COPY %WINDIR%\System32\drivers\etc\lmhosts.sam Net_lmhosts_sam.txt /Y');
    #system('Msinfo32.exe /nfo msinfo.nfo');
    getEVT("Application.html", 'Application');
    getEVT("System.html", 'System');
    #get DataAccess data, which includes MDAC info.
    regenum(\%sysdata, "MDAC.html");
    resetdir($curdir);
}


### File-pulling functions
### grabs actual files to the appropriate folder.

sub pullFile{
    my $files = shift;
    my $cur_dir = shift;
    foreach my $key (keys %{$files}){
        my $src_file = $files->{$key};
        my $dest_file = $cur_dir;
        my $cmd = "copy /Y \"$src_file\" \"$cur_dir/\"";
        if (-f $src_file){
            system($cmd) or warn "Can't copy file: $! \n";
        }
    }
}
### Reporting Functions
### At the Moment just display options for HTML.  Will improve this soon.

sub make_table{
 say "<table>";    
}

sub make_table_close{
    say "</table>";
}

sub make_row{
    my $records = shift;
    say "<tr>";
    foreach (@{$records}){
        if(defined($_)){
        say "<td> " . $_ . " </td>";
        } 
    }
    say "</tr>";
}


sub make_table_header{
        my $header = shift;
    say "<tr>";
    foreach (@{$header}){
        say "<th> " . $_ . " </th>";
    }
    say "</tr>";
}

sub make_header{
    my ($name,$type) = @_;
    say "<$type>" . $name . "</$type>";
}

sub make_html_open{
    my $html = <<'HTML';
<html>
<head>
    <title>NTP QFS Post Validation Report</title>
        <STYLE type="text/css">
            body {
                margin:10px;
                font-family:Arial, sans-serif;
                font-size: 12px
                color: #000;
                background-color: #fff;
            }
            h1 {border-width: 0;  font-size: 18px}
            h2 {border-width: 0;  font-size: 16px}
            h3 {border-width: 0;  font-size: 14px}
            table { width: 100%; cell-spacing: 5px; border: 1px #fff solid; }
            td {cell-spacing: 5px; }
        </STYLE>
</head>

<body>
HTML

say $html;

}

sub make_html_close{
    say "</body>";
    say "</html>";
}

sub createIndex{
    #my $curdir = getcwd;
    #say $curdir;
    #exit;
    open(NAV,">../info/nav.html") || die "Can't create index.";
    select(NAV);
    make_html_open();
    opendir my($dh), "../info" or die "Couldn't open directory: $!";
    my @files = readdir $dh;
    closedir $dh;
    foreach(@files){
        if ($_ eq '.' || $_ eq '..'){next;}
        if ($_ eq 'index.html' || $_ eq 'nav.html' || $_ eq 'blank.html' || /\.evt/){next;}
                make_header($_,"h2");
                my $path = "../info/$_";
                my $relpath = "$_";
                opendir my($sh), $path or say "can't open directory: $!";
                my @sfiles = readdir $sh;
                closedir $sh;
                foreach(@sfiles){
                    if ($_ eq '.' || $_ eq '..'){next;}
                    say "<a href=\'$relpath\/" . $_ . "\' target=\"center\">" . $_ . "</a><br />";
                }
        
    }
    make_html_close();
    handleswitch('NAV');
}

sub createFrame{
    
#HTML in heredoc form.
    my $frame_html = <<'FRAME';
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<HTML>
<HEAD>
<TITLE>NTP Gatherer</TITLE>
</HEAD>
<FRAMESET cols="20%, 80%">
    <FRAME name="sidenav" src="nav.html">
    <FRAME name="center" src="blank.html">
</FRAMESET>
</HTML>
FRAME

    my $blank_html = <<'BLANK';
<HTML>
<HEAD>
<TITLE>NTP Information Gatherer</TITLE>
        <STYLE type="text/css">
            body {
                margin:10px;
                font-family:Arial, sans-serif;
                font-size: 12px
                color: #000;
                background-color: #fff;
            }
            h1 {border-width: 0;  font-size: 18px}
            h2 {border-width: 0;  font-size: 16px}
            h3 {border-width: 0;  font-size: 14px}
            table { width: 100%; cell-spacing: 5px; border: 1px #fff solid; }
            td {cell-spacing: 5px; }
        </STYLE>
</HEAD>
    <body>
    </body>
</HTML>
BLANK

    open(INDEX,">../info/index.html") || die "Can't create index.";
    select(INDEX);
    print $frame_html;
    handleswitch('INDEX');
    
    #print the blank page
    open(PLACEHOLDER,">../info/blank.html") || die "Can't create index.";
    select(PLACEHOLDER);
    print $blank_html;
    handleswitch('PLACEHOLDER');
}

# Helper Functions.

sub handleswitch{
    my $handle = shift;
    close($handle);
    open (STDOUT, ">-");
    select(STDOUT);
}

sub switchdir { #switch directories in the ino directory
    my $dirname = shift;
    my $path = "../info/$dirname";
    mkpath ($path);
    chdir($path);
}

sub execdir { #switch to bin for scripts.
    my $path = "../bin";
    mkpath ($path);
    chdir($path);
}

sub resetdir{
    my $dirname = shift;
    chdir($dirname);
}

1;
