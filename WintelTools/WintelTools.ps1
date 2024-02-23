<# WintelTools - https://github.ibm.com/Continuous-Engineering/wintel-tools
8.2.2021 new patchreport to list all installed KBs on servers (via get-hotfix)
2.2.2021 ip is now being taken from AD in case server does not ping but RDP port responds
new patchreport with KBs list
19.7.2020 added mode switching
16.5.2020 added check for registry scheduledinstallday 0 = any
20.4.2020 Vitezslav - adding scan for PSversion and PowerShellMem into get information about servers in domain
19.4.2020 Vitezslav - redoing WU functions
11.3.2020 Vitezslav - $lastpatchdate bugfix - in case of error there was value from previous server checked               
31.1.2020 Vitezslav - added OP5 and SNMP service check
17.1.2020 Vitezslav - fixed timed out machines not being added to final result
21.12.2019 Vitezslav - script does not end after an action
    added WUtasks update
    added DMZ logs collector
24.11.2019 Vitezslav - disk space report functionality added
19.10.2019 Vitezslav - new HTML patch report
6.9.2019 Vitezslav - OS info is taken from AD object if WMI is not working
8.8.2019 Vitezslav - ADscan is being retried on timed-out hostnames
25.7. Vitezslav - changed choice 3 to only scan for KBs and server online status in hope of speeding up the script
3.4. Vlad - Adapter MAC address check. 
#>
param([string]$action,[string]$list,[string]$creds,[string]$par,[string]$html,[string]$reportname,[string]$reportpath,[string]$htmlpath,[string]$mode)
$fileversion="1.0.7.3"

function resetxmlsettings(){
'<?xml version="1.0"?>
<settings>
<lasthostgroup></lasthostgroup>
<loadlasthostgroup>true</loadlasthostgroup>
<inventory>
<maxparallel>100</maxparallel>
</inventory>

<fileoperations>
<maxparallel>10</maxparallel>
</fileoperations>

<monitoring>
<servicesToIgnore>
;;RemoteRegistry;NO_MONIT;;;;;;
;;ShellHWDetection;NO_MONIT;;;;;;
;;SysmonLog;NO_MONIT;;;;;;
;;clr_optimization_.*;NO_MONIT;;;;;;
;;gupdate;NO_MONIT;;;;;;
;;sppsvc;NO_MONIT;;;;;;
;;stisvc;NO_MONIT;;;;;;
;;wuauserv;NO_MONIT;;;;;;
;;TBS;NO_MONIT;;;;;;
;;Shavlik Scheduler;NO_MONIT;;;;;;
;;CA-HAOSVC;NO_MONIT;;;;;;
;;awservices;NO_MONIT;;;;;;
;;AppFabricCachingService;NO_MONIT;;;;;;
;;WinHttpAutoProxySvc;NO_MONIT;;;;;;
;;VSS;NO_MONIT;;;;;;
;;AenService;NO_MONIT;;;;;;
;;TSM Client Acceptor;NO_MONIT;;;;;;
;;TrustedInstaller;NO_MONIT;;;;;;
;;MapsBroker;NO_MONIT;;;;;;
;;WbioSrvc;NO_MONIT;;;;;;
;;CDPSvc;NO_MONIT;;;;;;
;;Ati HotKey Poller;NO_MONIT;;;;;;
;;pgsql-8.4;NO_MONIT;;;;;;
;;MSIServer;NO_MONIT;;;;;;
;;DsmSvc;NO_MONIT;;;;;;
;;AeLookupSvc;NO_MONIT;;;;;;
;;DeviceInstall;NO_MONIT;;;;;;
;;SplunkForwarder;NO_MONIT;;;;;;
;;Emulex HBA Management;NO_MONIT;;;;;;
;;NAIMServInst;NO_MONIT;;;;;;
;;panwd;NO_MONIT;;;;;;
;;telemetryServer;NO_MONIT;;;;;;
;;Telemetryserver;NO_MONIT;;;;;;
;;BMR Boot Service;NO_MONIT;;;;;;
;;RTMAService;NO_MONIT;;;;;;
;;BITS;NO_MONIT;;;;;;
;;CbDefenseWSC;NO_MONIT;;;;;;
;;tiledatamodelsvc;NO_MONIT;;;;;; 
</servicesToIgnore>
</monitoring>
</settings>'|out-file "settings.xml" -force
}
if(!(test-path "settings.xml")){ resetxmlsettings }     # create default settings.xml

function loadsettings(){
    if(!(test-path "settings.xml")){ return }
    [xml]$global:ConfigFile=Get-Content "settings.xml"
    if($debug -eq 1){
     $configfile.settings.loadlasthostgroup
     $configfile.settings.inventory.maxparallel

    }
}

function savesettings(){
    $configfile.save("$dir\settings.xml")
}

function rootmenu{
param($clear=$true)
if($clear -and $debug -eq 0){ clear-host }
write-host " __    __ _       _       _   _____            _     
/ / /\ \ (_)_ __ | |_ ___| | /__   \___   ___ | |___ 
\ \/  \/ / | '_ \| __/ _ \ |   / /\/ _ \ / _ \| / __|
 \  /\  /| | | | | ||  __/ |  / / | (_) | (_) | \__ \
  \/  \/ |_|_| |_|\__\___|_|  \/   \___/ \___/|_|___/" -ForegroundColor yellow
write-host "version: $fileversion  operation mode: "($appstatus.mode) -ForegroundColor cyan
write-host "=================================================================="
#$PSDefaultParameterValues += @{ '*:ForegroundColor' = 'Gray' }
$host.UI.RawUI.ForegroundColor="Gray"
if($appstatus.mode -eq "winrm"){
    write-host "for WinRM mode you need to load credentials and currenly only patch report uses this (choice 4,1)" -foregroundcolor cyan
    if($appstatus.credentialname){$color="gray"}else{$color="red"}
    write-host "credentials loaded: "($appstatus.credentialname) -foregroundcolor $color
    write-host "PSsessions active: "($appstatus.pssessions)
}
write-host "hostgroup name:" -nonewline
if($appstatus.groupname){write-host ($appstatus.groupname) -foregroundcolor yellow -nonewline}
write-host " saved:"($appstatus.groupsaved)
write-host "hosts loaded: " -nonewline
if($appstatus.hostsloaded){ write-host "true" -foregroundcolor green -nonewline }else{ write-host "false" -nonewline}
write-host " count:"($appstatus.hostcount) -nonewline
if($appstatus.resultcount){ write-host "last result count:"($appstatus.resultcount) }
#$PSDefaultParameterValues += @{ '*:ForegroundColor' = 'white' }
$host.UI.RawUI.ForegroundColor="White"
write-host 
write-host "load " -ForegroundColor yellow -NoNewline; write-host "- load hostnames/IPs from TXT"
write-host "paste " -ForegroundColor yellow -nonewline; write-host "- paste hostnames/IPs from TXT from clipboard"
write-host "save - save current host group into file"
write-host "s - show current list"
if($appstatus.lastresultdata){ write-host "r - show last results" }
write-host
write-host "0 - manage credentials or switch mode"
if($appstatus.mode -eq "domain"){ write-host "1 - Inventory scan"}
if($appstatus.mode -eq "domain"){ write-host "2 - File operations"}
if($appstatus.mode -eq "domain"){ write-host "3 - Monitoring tools"}
write-host "4 - Patching tools"   #for now majority of this functionality is in another package
if($appstatus.mode -eq "domain"){ write-host "5 - Deployment tools (partialy implemented)"}
write-host
$choice=read-host "select category"
if($debug -eq 1){ write-host "choice:$choice"}
return $choice
}

function credentialsmenu(){
write-host "application will primarily connect using currently loaded credentials and will look for specific credentials in case of SA server" -ForegroundColor cyan
write-host ""
if($appstatus.mode -eq "domain"){
    write-host "0 - switch mode to WinRM - this will work only with CSV lists in format hostname,IP."
    write-host "Currently only patchreport uses WinRM mode"
}else{
    write-host "0 - switch mode to domain - this will work with both TXT or CSV lists of hostnames or IPs"
}
write-host "1 - add new credentials"
write-host "2 - load credentials"
write-host "3 - import credentials from CSV"
write-host
write-host "4 - show opened PSsessions"
write-host
$choice=read-host "select an action. You will be asked about scope in next prompt"
return $choice

}

function inventorymenu(){
write-host "1 - quick status check of server(s) (ping, IP, AD OS)"
write-host "2 - get information about servers in domain"
write-host "3 - disk space report"
write-host "4 - agent removal report"
write-host "5 - WinRM test"
write-host "6 - .NET framework version check"
#write-host "5- TSM results summary - WIP"
write-host
$choice=read-host "select an action. You will be asked about scope in next prompt"
return $choice
}
function filemenu(){
write-host "1 - parallel copy files or folders"
write-host "2 - check if file/folder exists and it's version"
write-host "3 - watch file(s) content (FileWatcher in a new console window)"  #configurable detect rate and lines to show
write-host "4 - watch file(s) for a specific string (FileWatcher in a new console window)"  
write-host "5 - watch multiple files timestamp and size (not implemented yet)"  #paste paths into notepad (with some max number allowed)
$choice=read-host "select an action. You will be asked about scope in next prompt"
return $choice
}
function monitoringmenu(){
write-host "1 - pinger and TCP port checker"
write-host "2 - multi-pinger with logging of changes in time (not yet implemented)"
write-host "3 - service status"   #specific service or all auto services not running
write-host "4 - performance counters (CPU, mem, disk or custom)"
write-host "5 - eventlog get events"
write-host "6 - realtime eventlog viewer with advanced filtering"
$choice=read-host "select an action. You will be asked about scope in next prompt"
return $choice
}
function patchingmenu(){
if($appstatus.mode -eq "domain"){
    write-host "1 - patching status report HTML and CSV with KBs and events from last day of patching"
    write-host "2 - patching report for specific KBs"
    write-host "3 - WindowsUpdate registry results (w2k12 and lower)"
    write-host "4 - list all KBs installed on servers (one KB per line)"
    write-host "5 - list all KBs installed on servers (KBs in columns)"
}

$choice=read-host "select an action. You will be asked about scope in next prompt"
return $choice
}
function deploymentmenu(){
write-host "1 - run IAM_extract on remote servers (stand-alone servers)"
#write-host "2 - run IAM_extract on remote servers (domain member servers)"
#write-host "this functionality will allow admin to mass deploy software packages"
#write-host "first copy files onto servers via file operations menu"
#write-host "second - this will create a scheduled task with a custom command and run it on target hosts as SYSTEM to install the package (common practice)"
#write-host "third - check results by reading logfile or eventlog"
#write-host "it is always advised to first do a test on a single server"
read-host "press enter to continue"
}
function resetgroupvars(){
    #clear-variable servers -scope global
    $appstatus.hostsloaded=$false
    #$appstatus.hostschecked=$false
    $appstatus.groupname=""
    #$global:servers=@()
}

function pastehosts(){
    start-process notepad.exe -argumentlist "hostgroups\list.txt" -wait
    $l = Get-Content "hostgroups\list.txt"
    $l=$l| ?{$_.Length -gt 2 } #strip lines shorter then 3 chars
    $l=$l.trim()   #trim spaces in the beginning and end of lines
    if($debug){
        $l
    }
    $global:appstatus.hostcount=($l|measure-object|select -expandproperty count)
    if($global:appstatus.hostcount -eq 0){
        write-host "file seems to be empty. 0 items loaded"
        read-host "press enter to contine"
        return ""
    }
    $global:appstatus.hostsloaded=$true
    $global:appstatus.csvlist=$null
    $global:appstatus.txtlist=$l
    $appstatus.filename="list.txt"
    if($debug -eq 1){read-host "press enter (debug)"}
    clear-host
}
   
function showhosts(){
        if(($appstatus.txtlist).count -gt 0){
            $appstatus.txtlist|out-host
        }else{
            $appstatus.csvlist|out-host
        }
}
function loadhosts($filename=""){
if(!$filename){
    $files=get-childitem -path "hostgroups\*"
    if($files){
        write-host "*.txt in hostgroups:"
        $files
    }
    $filename=read-host "type filename with hostnames/IPs"
}
if(!(test-path("hostgroups\$filename"))){
    write-host "ERROR - file not found hostgroups\$filename" -ForegroundColor Red
    read-host "press enter to contine"
    return
}
write-host "loading $filename"
if($filename -like "*.csv*"){
    $line=Get-Content "hostgroups\$filename" | Select -First 1
    $delimiter=if($line.Split(";").Length -gt 1){";"}else{","};
    $appstatus.csvlist=import-csv "hostgroups\$filename" -Delimiter $delimiter
    $appstatus.hostcount=($appstatus.csvlist|measure-object|select -expandproperty count)
    $appstatus.txtlist=@()
}else{
    $appstatus.txtlist = Get-Content "hostgroups\$filename"
    $appstatus.txtlist=$appstatus.txtlist.trim()   #trim spaces in the beginning and end of lines
    $appstatus.txtlist=$appstatus.txtlist| ?{$_.Length -gt 2} #strip lines shorter then 3 chars
    $appstatus.hostcount=($appstatus.txtlist|measure-object|select -expandproperty count)
    $appstatus.csvlist=@()
}
$appstatus.filename=$filename

if($appstatus.hostcount -gt 0){
    resetgroupvars
    write-host "loaded "($appstatus.hostcount)" hosts"
}else{
    write-host "file seems to be empty. 0 items loaded"
    if(!$appstatus.unattended){ read-host "press enter to continue" }
    return
}
$appstatus.hostsloaded=$true
$time=[DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
write-host "loaded hostgroups\$filename -"$appstatus.hostcount"lines"
if($appstatus.hostcount -lt 10){
    if($appstatus.txtlist){ $appstatus.txtlist}
    if($appstatus.csvlist){ $appstatus.csvlist}
}
write-host $time -ForegroundColor Cyan
if($debug){
    read-host "press enter to continue"
}else{
    if(!$appstatus.unattended){ start-sleep 1}
}
$appstatus.hostsloaded=$true
}

function savehostgroup(){
    $n=read-host "type hostgroup name (without file extension)"
    if(!$n){
        "it cannot be blank!"
        return
    }
    $appstatus.groupname=$n
    if(!(test-path "hostgroups")){ new-item "hostgroups" -ItemType directory}
    $global:list|out-file "hostgroups\$n.txt"
    if(test-path "hostgroups\$n.txt"){
        $appstatus.groupsaved=$true
    }
    clear-host
}
function filewatcher($mode=""){
    write-host "includes/FileWatcher.ps1 - you can use this script separately" -ForegroundColor Cyan
    write-host "specify path to watch. Local or network path to file or folder and it can even be non existent/empty yet. If you use wildcard it will watch multiple files"
    $filename=read-host "enter path"
    "opening script in new console window to run independently"
    $powershellPath = "$env:windir\system32\windowspowershell\v1.0\powershell.exe"
    start-Process $powershellPath -ArgumentList "-command $dir\includes\filewatcher.ps1 '$filename' '$mode'"
    read-host "press enter to go back to main menu"
}
function eventlog(){
    write-host "includes/eventlog.ps1 - you can use this script separately" -ForegroundColor Cyan
    "opening script in new console window to run independently"
    $powershellPath = "$env:windir\system32\windowspowershell\v1.0\powershell.exe"
    start-Process $powershellPath -ArgumentList "-command $dir\includes\eventlog.ps1"
    read-host "press enter to go back to main menu"
}
function importcredentialsfromCSV(){
    write-host "paste table with headings: hostname,domain,usr,pwd"
    write-host "leave domain empty for stand-alone servers"
    start-process notepad.exe -argumentlist "accs.csv" -wait
    $accs=import-csv "accs.csv"
    remove-item "accs.csv"
    foreach($ac in $accs){
        $password = ConvertTo-SecureString $ac.pwd -AsPlainText -Force
        if($ac.domain){
            $usr=$ac.domain+"\"+$ac.usr
        }else{
            $usr=$ac.usr
        }
        write-host $usr
        write-host $password
        $psCred = New-Object System.Management.Automation.PSCredential -ArgumentList ($usr, $password)
        $name=$ac.hostname
        $pscred|export-clixml $env:appdata"\creds\SA\"$name".xml"
        write-host "saved as "$env:appdata"\creds\SA\"$name".xml" -foregroundcolor yellow
    }
}


function addcredentials(){
    $credential = Get-Credential
    $name=read-host "type name of the credential set (customer name or server IP)"
    if(!(test-path $env:appdata"\creds")){new-item $env:appdata"\creds" -ItemType directory}
    if($name -like "*.*.*.*"){
        if(!(test-path $env:appdata"\creds\SA")){new-item $env:appdata"\creds\SA" -ItemType directory}
        if(test-path $env:appdata"\creds\SA\"$name".xml"){
            write-host "this credential set already exists!" -ForegroundColor yellow
            $q=read-host "overwrite?"
            if($q -eq "y" -or $q -eq "Y" -or $q -eq "z" -or $q -eq "Z"){
                remove-item $env:appdata"\creds\SA\"$name".xml"
            }else{
                return
            }
        }
        $credential| export-clixml $env:appdata"\creds\SA\"$name".xml"
    }else{
        if(test-path $env:appdata"\creds\"$name".xml"){
            write-host "this credential set already exists!" -ForegroundColor red
            $q=read-host "overwrite?"
            if($q -eq "y" -or $q -eq "Y" -or $q -eq "z" -or $q -eq "Z"){
                remove-item $env:appdata"\creds\SA\"$name".xml"
            }else{
                return
            }
        }
        $credential| export-clixml $env:appdata"\creds\"$name".xml"
    }
    loadcredentials $name
}
function loadcredentials{
    param([string]$fn)
    if($fn){"loading credentials $fn" ;start-sleep 1}
    if(!$fn){
        if(test-path $env:appdata"\creds"){
            write-host "looking for hostgroups in "$env:appdata"\creds"
            clear-variable files -ErrorAction silentlycontinue
            $filesc=get-childitem -path $env:appdata"\creds\*.xml"
            if($filesc){
                write-host $filesc
                write-host ""
            }else{
                write-host "no XML files found"
            }
        }else{
            write-host "no XML files found in "$env:appdata"\creds"
            read-host "press enter to continue"
            clear-host
            return
        }
        $fn=(read-host "enter file name without extension (leave blank if you want to cancel the action)").trim()
        if($filesc -and $fn -eq ""){ return}
    }
    if(!(test-path $env:appdata"\creds\"$fn".xml") -or $fn -eq ""){
        write-host $env:appdata"\creds\"$fn".xml not found"
        read-host "press enter to continue"
        clear-host
    }else{
        $appstatus.Credentials=Import-CliXml -Path $env:appdata"\creds\"$fn".xml"
        $appstatus.credentialname=$fn
        write-host "loaded credentials $fn"
        write-host $appstatus.Credentials
        if(!$appstatus.unattended -and $debug){ read-host "press enter to continue"}
    }
}
function switchmode(){
    if($appstatus.mode -eq "domain"){
        $appstatus.mode="WinRM"
    }else{
        $appstatus.mode="domain"
    }
}
function HTMLexport(){
    if($appstatus.htmlpath){
        $hpath=$appstatus.htmlpath
    }else{
        $hpath=".\webapp\"
    }
    if($appstatus.reportname){
        $fname=$hpath+$appstatus.reportname+".html"
    }else{
        $lastaction=$appstatus.lastaction
        $fname=$hpath+"$lastaction.html"
    }
    if($debug -eq 3){
        "initObj:"
        $initobj
    }
    <#if($action -eq "patchreport"){
        $initobj|select-object hostname,osshort,ip,lastpatchdate,lastboot|export-csv "initobj.csv"
    }else{
        $initobj|export-csv "initobj.csv"
    }#>
    if(test-path $fname){
        $fn=(get-item $fname)
        $newfn=$action+"-"+$fn.lastwritetime.ToString('dd-MM-yyyy_hh-mm')+".html"
        $newfn
        if(!(test-path .\webapp\oldreports)){new-item .\webapp\oldreports -ItemType directory}
        copy-item $fname .\webapp\oldreports\$newfn
    }
    gc "webapp\head.txt"|out-file $fname
    "<h2>$lastaction</h2>"|out-file $fname -append
    if($appstatus.resultcount -gt 300){
        "warning: if number of servers is bigger then 300. The OS information might be incorrect :("|out-file $fname -append
    }
    '<table width="100%" class="table table-striped table-bordered table-hover" id="dataTables-example">'|out-file $fname -append
    
    if($action -eq "patchreport"){
        $appstatus.lastresultdata|select-object hostname,osshort,ip,lastpatchdate,lastboot|convertto-html -fragment|out-file "fragment.txt"
    }else{
        $appstatus.lastresultdata|convertto-html -fragment|out-file "fragment.txt"
    }
    $lines=gc "fragment.txt"
    $c=0
    foreach($line in $lines){
        $c++
        #$c
        #$line
        if($c -lt 3){continue}
        if($c -eq 3){
            "<thead>"|out-file $fname -append
            $line|out-file $fname -append
            "</thead>"|out-file $fname -append
            "<tbody>"|out-file $fname -append

        }
        if($c -gt 3 -and $line -ne "</table>"){
            $line|out-file $fname -append
        }
        if($line -eq "</table>"){ continue }
    }
    gc "webapp\tail.txt"|out-file $fname -append
    write-host "$fname refreshed" -ForegroundColor cyan

}

function HTMLexportPatches(){
     if(test-path .\webapp\patchingStatus.html){
        $fn=(get-item .\webapp\patchingStatus.html)
        $newfn="report-"+$fn.lastwritetime.ToString('dd-MM-yyyy_hh-mm')+".html"
        $newfn
        copy-item .\webapp\patchingStatus.html .\webapp\oldreports\$newfn
     }
     gc "webapp\headp.txt"|out-file "webapp\patchingStatus.html"
     $kbs=@()
     $first=$appstatus.lastresultdata|select -first 1
     foreach($object_properties in $first.PsObject.Properties){
          if($object_properties.Name -like "KB*" -and $object_properties.Name -notlike "*_event"){
            if(!($kbs.contains($object_properties.Name))){ $kbs+=$object_properties.Name}
          }
     }
     if($paramsobj.withkbs){
        if($debug -eq 2){"foreach KBs: $kbs"}
         foreach($kb in $kbs) {
             ('<th>'+$kb+'</th>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         }
     }
     "</tr></thead><tbody>"|out-file "webapp\patchingStatus.html" -append
     #columns generated - now rows
     if($debug){
        "--------------appstatus.lastresultdata--------------"
        $appstatus.lastresultdata
     }
     "generating webapp\patchingStatus.html... (this is not very fast yet...)"
     $c=0
     $appstatus.lastresultdata|foreach {
         $c++
         $p=$c/$appstatus.resultcount*100
         $act=("generating HTML $c/"+$appstatus.resultcount)+"rows"
         Write-Progress -Activity $act -PercentComplete $p
         $class="text-muted"
         $result=""
         if($_.online -and $_.lasteventmessage -notlike "*error*"){$class="success"; $result="done"}
         if($paramsobj.withkbs){
            if($debug -eq 2){"withKBs foreach:"}
             foreach($kb in $kbs) {
                #if($debug){"  "+($_.($kb+"_event"))}
                 if($_.($kb+"_event") -eq "initiating"){ $class="warning"; $result="initiating" }
                 if($_.($kb+"_event") -eq "reboot necessary"){ $class="warning"; $result="reboot necessary" }
             }
         }
         ('<tr class="'+$class+'"><td>'+$_.hostname+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td>'+$_.type+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td>'+$_.osshort+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td>'+$_.online+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         #('<td>'+$_.rdp+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td nowrap>'+$_.lastpatchdate+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td nowrap>'+$_.lastboot+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td nowrap>'+$_.WU_requiresReboot+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td nowrap class="small">'+$_.lasteventmessage+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td nowrap>'+$_.lasteventtime+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
         ('<td>'+$result+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
 
         if($paramsobj.withkbs){
             foreach($kb in $kbs) {
                 $class=""
                 #if($debug -eq 2){ "<td>"+$_.($kb)}
                 if($_.($kb+"_event") -eq "initiating" -or $_.($kb+"_event") -eq "reboot necessary"){ $class="danger"}
                 ('<td class="'+$class+'">'+$_.($kb)+' '+$_.($kb+"_event")+'</td>')|out-file "webapp\patchingStatus.html" -append -NoNewline
             }
         }
         "</tr>"|out-file "webapp\patchingStatus.html" -append
     }
     gc "webapp\tail.txt"|out-file "webapp\patchingStatus.html" -append
 
     "wegbapp\patchingStatus.html refreshed"
}

if($reportpath){
    if($reportpath -notlike "*\"){$reportpath+="\"}
}
if($htmlpath){
    if($htmlpath -notlike "*\"){$htmlpath+="\"}
}
if($mode){
    if(!($mode -eq "domain" -or $mode -eq "winrm")){
        write-host "valid modes are domain or winrm" -ForegroundColor Red
        return
    }
}


$debug=$false
if($debug){
write-host "creds:$creds"
write-host "params: "$args.count 
}
"WintelTools loading modules..."
Import-Module activedirectory -erroraction silentlycontinue
if(!$?){
    write-host "activedirectory module missing. Some functionality will be limited" -ForegroundColor cyan
}
if($debug){"list:$list"}
if($debug){"reportname:$reportname"}
if($debug){"par:$par"}
$scriptpath=$MyInvocation.MyCommand.Path
$dir=Split-Path $scriptpath
cd $dir
$isadmin=([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if(!$isadmin){
    write-host "you need to run this as administrator" -ForegroundColor red
    return
}

$requiredfiles=(
"includes\FileWatcher.ps1",
"includes\eventlog.ps1"
)
$modules=(
"Invoke-Parallel.ps1",
"includes\patchreport-WinRM.ps1",
"includes\otherfuncs.ps1",
"includes\inventory.ps1",
"includes\customfuncs.ps1"
)
foreach($f in ($requiredfiles + $modules)){
    if(!(test-path $f)){
        write-host "WARNING - $f missing - some functions might be unavailable" -ForegroundColor yellow
    }
}

$starttime = (Get-Date -UFormat "%Y-%m-%d %H:%M")
$withkbs=$false

$global:appstatus=[pscustomobject] @{
    mode="domain"
    hostsloaded=$false
    hostcount=0
    filename=""
    credentialname=""
    credentials=$null
    groupname=$null
    groupsaved=$false
    resultcount=0
    lastresultdata=@()
    lastaction=""
    unattended=$false
    pssessions=0
    txtlist=@()
    csvlist=@()
    reportname=$reportname
    htmlpath=$htmlpath
}
if($mode -eq "winrm"){ $appstatus.mode="winrm"}
if($mode -eq "domain"){ $appstatus.mode="domain"}


if($debug -ne 2){
 foreach($f in $modules){
    if((test-path $f)){
        . .\$f
        if(!$?){
            write-host "ERROR loading $f! Fix module and try again" -ForegroundColor yellow
            return
        }
    }
 }
}

$wutask=""
$run=$true
$kbs=""
  $paramsobj=[pscustomobject] @{
    action=$action
    SRname=$SRname
    OScheck=$oscheck
    withKBs=$false
    withevents=$true
    wutask=$wutask
    command=""
    workdir=""
    files=""
    SAcredlist=@()
    csvlist=@()
    destination=""
    credentials=$null
    par=$par
    dir=$dir
    mode=""
    logname=""
    servicestoignore=@()
    eventids=@()
    days=0
    #getDMZcreds=$function:getDMZcreds
 }
 
 <#"----DEBUG----"
 $appstatus.lastresultdata=import-csv "res.csv"
 $paramsobj.logname="application"
 $paramsobj.eventids=(900,902,1023)
 $paramsobj.days=1
 "----DEBUG----"
 #>
if(($action -and $list) -or $action -eq "scanservers"){   #scanservers doesn't require parameter list
    $appstatus.unattended=$true
    "started with arguments:"
    $args
    if($debug){ read-host "DEBUG press enter to continue"}
}
if($list){
    write-host " $list"
    loadhosts($list)
}
if($action){
    write-host "started with parameters: $action"
    if($action -eq "scanservers"){ " TIP: if you run scanservers action and you don't specify second parameter, all servers in domain will be scanned" }
    if(!$appstatus.hostsloaded -and $action -ne "scanservers"){
        "if you want to run this unattended use two parameters: -action actionname -list filename (list of hostnames/IPs)"
        return
    }
}

if($creds){
    write-host "creds:$creds"
    loadcredentials($creds)
}

if(!(test-path "hostgroups")){ new-item "hostgroups" -ItemType directory}
if(!(test-path "webapp")){
    write-host "extracting webapp.zip..."
    new-item "webapp" -ItemType directory
    expand-archive -path webapp.zip -destinationpath .\webapp\
}
loadsettings
$settingsloaded=$true
$configfile.monitoring.servicesToIgnore
if([int]$configfile.settings.inventory.maxparallel -is [int]){
 #"it's INT"
}else{ #"no int"
    write-host "WARNING: settings.xml maxparallel value does not seem to be a number! Using default value of 100"
    $configfile.settings.inventory.maxparallel="100"
}
#read-host "debug"

try{[int]$configfile.settings.inventory.maxparallel}catch{
 $settingsloaded=$false
}
if(!$settingsloaded){
    write-host "ERROR reading settings.inventory.maxparallel from settings.xml"
    write-host "do you want to reset XML to default?"
    $r=read-host
    if($r -eq "y" -or $r -eq "yes"){
        resetxmlsettings
        loadsettings
        read-host "press enter to continue"
    }else{ return }
}

while($run){                  #MAIN CYCLE
 $pastedata=$false
 if(!$appstatus.unattended){
    $choice=rootmenu
    #write-host "choice:$choice"
    #read-host
    $action="nic"
    switch($choice){
        "html"{
        htmlexport
        break
        }
        "load"{
        loadhosts
        $action="load"
        break
        }
        "save"{
        savehostgroup
        $action="save"
        break     
        }
        "paste"{
        pastehosts
        showhosts
        #read-host "press enter to continue (debug)"
        break
        }
        "s"{
        "current list:"
        showhosts
        "---"
        read-host "press enter to continue"
        clear-host
        break
        }
        "r"{
        "last result data:"
        $appstatus.lastresultdata
        "---"
        read-host "press enter to continue"
        clear-host
        break
        }
        0{
        $choice2=credentialsmenu
        switch($choice2){
            0{
            switchmode
            break
            }
            1{
            addcredentials
            break
            }
            2{
            loadcredentials
            break
            }
            3{
            #$action="testcredentials"
            importcredentialsfromCSV
            }
            4{
            get-pssession
            read-host "press enter to continue"
            clear-host
            }
        }
        break
        }
        1{
        $choice2=inventorymenu
        switch($choice2){
            1{
            $action="quickscan"
            break
            }
            2{
            $action="scanservers"
            break
            }
            3{
            $action="diskspace"
            }
            4{
            $action="agentremovalreport"
            }
            5{
            $action="winrmtest"
            }
            6{
            $action="netframeworkcheck"
            }
        }
        break
        }
        2{
        $choice2=filemenu
        switch($choice2){
            1{ $action="filecopy"; break}
            2{ $action="filecheck"; break}
            3{ filewatcher; break}
            4{ filewatcher("s"); break}
            5{ $action="filewatch2"; break}
        }
        break
        }
        3{
        $choice2=monitoringmenu
        switch($choice2){
            1{ $action="portchecker"; break}
            2{ $action="pingmon"; break}
            3{ $action="servicecheck"; break}
            4{ $action="perfmon"; break}
            5{ $action="getevents"; break}
            6{ eventlog; break}
        }
        break
        }
        5{
        $choice2=deploymentmenu
        switch($choice2){
            1{ $action="runcommand"; break}
        }
        break
        }
        4{
        $choice2=patchingmenu
        switch($choice2){
            1{ $action="patchreport"; $paramsobj.withkbs; break}
            2{ $action="patchreportKBs"; break}
            3{ $action="wuregcheck"; break}
            4{ $action="patchreportall"; break}
            5{ $action="patchreportallKBcols"; break}
        }
        break
        }
        default{ "wrong choice!";$action="nic"; start-sleep 1; clear-host; break}
    }
    if($action -eq "nic" -or $action -eq "load" -or $action -eq "save"){continue}
    #read-host "after first switch"
 
 
    "select scope"
    "action: $action"
    if($action -eq "scanservers"){
        $paramsobj.SRname=read-host "type customer name (this will be a column in resulting table)"
        "1 - all member servers in current domain"
    }else{write-host}
        if($debug -eq 1){
            write-host "appstatus.txtlist:"
            write-host $appstatus.txtlist
            write-host "appstatus.csvlist:"
            write-host $appstatus.csvlist
            "===="
        }
        if($appstatus.txtlist -or $appstatus.csvlist){
            write-host "2 - currently loaded list ("($appstatus.hostcount)"hosts)"
        }else{ write-host }
        write-host "3 - paste hosts/IPs"
        write-host "4 - load from file"
        $choice=read-host "select scope"
        switch($choice){
        1{
            $appstatus.txtlist = Get-ADComputer -Filter {OperatingSystem -like "*server*" -and enabled -eq $true} -property * | ForEach-Object {$_.Name}
            $appstatus.hostcount=($appstatus.txtlist|measure-object|select -expandproperty count)
        }

        2{     }
        3{
            pastehosts
        }
        4{loadhosts}
    }

    if($action -eq "getevents"){
      write-host "enter logname (eg. application/setup/system)"
      $logname=read-host
      if($logname -eq ""){
            "this cannot be empty"
            continue
      }
      write-host "enter eventids (numbers separated by ,) or leave empty for any"
      $eventids=read-host
      write-host "enter how many days into past to search"
      $days=read-host
      $paramsobj.logname=$logname
      $paramsobj.eventids=$eventids
      $paramsobj.days=$days
    }
 }
 
 $paramsobj.SAcredlist=get-childitem -path $env:appdata"\creds\sa\*.xml" -erroraction silentlycontinue|select name
 
 if($appstatus.mode -eq "winrm"){
    if(!$appstatus.Credentials){
        write-host "credentials not loaded! You need to run script with parameter -creds filename (without extension)" -foregroundcolor red
        return
    }
    $paramsobj.credentials=$appstatus.Credentials
    $paramsobj.mode="winrm"
 }
 if($appstatus.unattended -and $action -eq "scanservers"){
    write-host "version: $fileversion  operation mode: "($appstatus.mode) -ForegroundColor cyan
    if($reportname){
        $paramsobj.SRname=$reportname
    }else{
        $paramsobj.SRname="customer"
    }
    if(!($appstatus.txtlist -or $appstatus.csvlist)){
        $appstatus.txtlist = Get-ADComputer -Filter {OperatingSystem -like "*server*" -and enabled -eq $true} -property * | ForEach-Object {$_.Name}
        $appstatus.hostcount=($appstatus.txtlist|measure-object|select -expandproperty count)
    }
 }
 
  $paramsobj.action=$action
  $appstatus.lastaction=$action
  if($action -eq "patchreport"){
      <#$filename="kbs.txt"
      if(!(test-path($filename))){
            write-host "in the following notepad paste list of KBs to get information about (one per line)" -ForegroundColor cyan
            write-host "save empty file if you don't want specific KB information"
            read-host
      }
      start-process notepad.exe -argumentlist KBs.txt -wait
      $kbs=Get-Content $filename
      $paramsobj.KBs=$kbs
      "loaded kbs.txt"
      $paramsobj.KBs
      if($paramsobj.KBs){
        "withKBS=true"
        $paramsobj.withkbs=$true
      }
      $paramsobj.dayshistory=read-host "how many days of eventlog history to search for events?"
      #>
      $paramsobj.withkbs=$true

  }

 if($appstatus.hostcount -eq 0) {
  write-host "no hostlist"$appstatus.hostcount
  if(!$appstatus.unattended){ read-host "press enter to continue"; continue}else{return}
 }

 if($debug){
    "params:"
    $paramsobj
 }
 if(!$appstatus.unattended -and ($action -eq "scanservers" -or $action -eq "quickscan" -or $action -eq "patchreport")){
  write-host "command for unattended run:"
  write-host $MyInvocation.MyCommand.Path" -action $action" -ForegroundColor Cyan -NoNewline
  if($appstatus.filename){ write-host " -list"($appstatus.filename) -ForegroundColor Cyan -NoNewline }
  if($appstatus.credentialname){ write-host " -creds"($appstatus.credentialname) -ForegroundColor Cyan -NoNewline }
  write-host ""
 }else{
  write-host "action: $action" -ForegroundColor Cyan
 }
 if(!$appstatus.unattended -and $appstatus.filename){ write-host "("($appstatus.filename)"must be in folder hostgroups)"}
 $totalcount=$appstatus.hostcount
 #"total host count: $totalcount"
 if($totalcount -gt 300){$oscheck=$false}else{$oscheck=$true}
 if($debug -eq 2){$paramsobj}

 
 if(test-path("c:\temp\TimedOutHostnames.txt")){ remove-item("c:\temp\TimedOutHostnames.txt") }
 $starttime=(get-date)

 write-host ([DateTime]::Now.ToString("yyyy/MM/dd HH:mm:ss"))" operating on $totalcount hosts" -ForegroundColor yellow

 clear-variable res -ErrorAction SilentlyContinue
    if($appstatus.mode -eq "winrm"){
        if($appstatus.csvlist){
            $paramsobj.csvlist=$appstatus.csvlist
            $hostlist=$appstatus.csvlist|select -expandproperty ip
        }else{
            $hostlist=$appstatus.txtlist
        }
    }else{
        if($appstatus.csvlist){
            $hostlist=$appstatus.csvlist|select -expandproperty hostname
        }else{
            $hostlist=$appstatus.txtlist
        }
    }

 switch($action){
  "quickscan"{
     $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBquick
  }
  "netframeworkcheck"{
     $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SB_NETframework
  }
  "WUregcheck"{
     $res=Invoke-Parallel -InputObject $hostlist -throttle 50 -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBWUreg
  }
  "diskspace"{
     $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBdiskspace
  }
  "agentremovalreport"{
     $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBagentremovalStatus
  }
  "getreboots"{
      $res=Invoke-Parallel -InputObject $hostlist -throttle 50 -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBreboots
  }
  "getevents"{
      write-host "1 - export results into single file"
      write-host "2 - export results into "($appstatus.hostcount)" files"
      $paramsobj.par=read-host "choose"
      $resevents=Invoke-Parallel -InputObject $hostlist -throttle 50 -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBgetevents
      $paramsobj
      if($paramsobj.par -eq 1){
        $res=@()
        foreach($obj in $resevents){
            foreach($evt in $obj.events){
                $line=$evt
                $line| Add-Member -MemberType NoteProperty -Name hostname -Value $obj.hostname
                $l=$line|select-object hostname,TimeCreated,Id,LevelDisplayName,ProviderName,Message
                $res+=$l
            }
        }
       }else{
        $res=$resevents
       }

  }
  "filecopy"{
      $paramsobj.files=read-host "type source folder or path (UNC is supported)"
      if(!(test-path $paramsobj.files)){
        write-host "ERROR - file not found" -ForegroundColor red
        if(!$appstatus.unattended){ read-host "press enter to continue" }
        $action="nic"
        break
      }
      do{
        $paramsobj.destination=read-host "type destination share\path\ (eg. c$\temp\)"
        $k=$paramsobj.destination.substring($paramsobj.destination.length-1,1)
        if($k -ne "\"){write-host "destination must end with \"}
      }while($k -ne "\")
      $q=read-host "are you sure you want to copy "($paramsobj.files)" to "($appstatus.hostcount)" hosts?"
      if(!($q -eq "y" -or $q -eq "yes")){
        "aborted"
        start-sleep 1
        $action="nic"
      }else{
       if($appstatus.mode -eq "winrm"){
        $paramsobj.mode="winrm"
       }else{
        $paramsobj.mode="normal"
       }
       if($debug){ $paramsobj}
       "starting copy with maximum 10 threads..."
       $rescopy=Invoke-Parallel -InputObject $hostlist -throttle 10 -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBcopyfiles
       $res=@()
       foreach($l in $rescopy){
        if($l.hostname){$res+=$l}
       }
      }
  }
  "runcommand"{
    write-host "type the command to run on target systems (next prompt will be working directory)"
      $paramsobj.command=read-host
      write-host "type working directory for the command on target systems (or leave empty)"
      $paramsobj.workdir=read-host
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBrunexe_SAservers
  }
  "filecheck"{
      write-host "type share\path (eg. c$\Program Files (x86)\Internet Explorer\iexplore.exe)"
      $paramsobj.files=read-host
      $filechecked=$paramsobj.files.split("\")|select -last 1
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBfilecheck
  }
  "winrmtest"{
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBwinrmtest
  }
  
  "portchecker"{
      $paramsobj.par=read-host "type TCP ports separated by comma (eg. 5985,443,80)"
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBportcheck
  }
  "servicecheck"{
      if($par -eq ""){
        write-host "type service name or displayname or leave empty to check all automatic services (wildcards supported)"
        $paramsobj.par=read-host
      }else{
        $paramsobj.par=$par
      }
      $paramsobj.servicestoignore=$configfile.settings.monitoring.servicesToIgnore
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBservicecheck
  }
  "perfmon"{
      write-host "leave empty to get common performance counters (see settings.xml) or specify custom counter separated by ,"
      write-host "(eg. \LogicalDisk(*)\Avg. Disk Queue Length,\Memory\Available MBytes)"
      $paramsobj.par=read-host
      if(!$paramsobj.par){
            $paramsobj.par=$configfile.settings.monitoring.defaultCounters
      }else{
        $paramsobj.par=($paramsobj.par) -replace ',',"`r`n"
      }
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBperfmon
  }
  "patchreportKBs"{
      $paramsobj.par=read-host "type KBs separated by ,"
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBpatchreportKBs
  }
  "patchreportall"{
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBpatchreportall
  }
  "patchreportallKBcols"{
      $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBpatchreportall2
  }
  "patchreport"{
     if($appstatus.mode -eq "winrm"){
        write-host "SAcredlist:"
        write-host $paramsobj.sacredlist
        $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBpatchreport_winrm
     }else{
        $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 120 -parameter $paramsobj -ScriptBlock $SBpatchreport
     }
  }

  
  
  "scanservers"{
    $res=Invoke-Parallel -InputObject $hostlist -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 100 -parameter $paramsobj -ScriptBlock $SBscanservers
    #$res|export-csv restemp.csv -NoTypeInformation
    clear-variable restimedout1 -ErrorAction SilentlyContinue
    clear-variable restimedout2 -ErrorAction SilentlyContinue
    if(test-path("c:\temp\TimedOutHostnames.txt")){
        $timedoutcount=(Get-Content "c:\temp\TimedOutHostnames.txt" | Measure-Object –Line).lines
        write-host "retrying scan on $timedoutcount timed out machines..." -ForegroundColor yellow
        $list=Get-Content "c:\temp\TimedOutHostnames.txt"
        remove-item("c:\temp\TimedOutHostnames.txt")
        $restimedout1=Invoke-Parallel -InputObject $list -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 40 -parameter $paramsobj -ScriptBlock $SB
        $restimedout1|export-csv "resTimedOut1.csv" -NoTypeInformation
    }
    if(test-path("c:\temp\TimedOutHostnames.txt")){
        $timedoutcount=(Get-Content "c:\temp\TimedOutHostnames.txt" | Measure-Object –Line).lines
        write-host "still $timedoutcount timed out machines - doing quick scan on them..." -ForegroundColor yellow
        $list=Get-Content "c:\temp\TimedOutHostnames.txt"
        $restimedout2=Invoke-Parallel -InputObject $list -throttle $configfile.settings.inventory.maxparallel -runspaceTimeout 20 -parameter $paramsobj -ScriptBlock $SBquick
        $restimedout2|export-csv "resTimedOut2.csv" -NoTypeInformation
    }
  }
 }
 if($action -eq "nic"){ continue}
 $stoptime=(get-date)
 $min=($stoptime-$starttime).minutes
 if($min -eq 0){$min="00"}
 $sec=($stoptime-$starttime).seconds
 if($sec -lt 10){$sec=("0"+$sec)}
 $ts=[DateTime]::Now.ToString("yyyy-MM-dd_HHmmss")
 if($action -eq "scanservers"){
     $SRname
     $namecsv=$SRname+"_ADscan.csv"
 }else{
    if($action -eq "filecheck"){
        $namecsv=$action+"_"+$filechecked+"_$ts.csv"
    }else{
        $namecsv=$action+"_$ts.csv"
    }
 }
 if($debug){"nameesvc:$namecsv"}
 if($reportname){ $namecsv=$reportname+".csv"}
 if($debug){"nameesvc:$namecsv"} 
 write-host ([DateTime]::Now.ToString("yyyy/MM/dd HH:mm:ss"))"operation took"$min":"$sec"s Export filename: reports\$namecsv" -ForegroundColor green
 #return
 $timedoutcount=0
 if(test-path("c:\temp\TimedOutHostnames.txt")){
    $timedoutcount=(Get-Content "c:\temp\TimedOutHostnames.txt" | Measure-Object –Line).lines
 }

 $numOnline=($res|where {$_.online -eq $true}|measure-object).count
 if($restimedout1){$numOnline+=($restimedout1|where {$_.online -eq $true}|measure-object).count}
 if($restimedout2){$numOnline+=($restimedout2|where {$_.online -eq $true}|measure-object).count}
 $numWSUS=($res|where {$_.UseWUServer -eq $true}|measure-object).count
 
 write-host "Statistics:" -ForegroundColor cyan
 "total servers: $totalcount"
 "timed out: $timedoutcount"
 "pingable servers: $numOnline"
 if($action -eq "scanservers"){ "in WSUS: $numWSUS"}

 
  #$initObj= New-Object -TypeName psobject 
  $firstrow=$res|select -first 1                    #this should initialize the table to have all columns from all rows
  $initObj=$firstrow
  $res|foreach{
      foreach($object_properties in $_.PsObject.Properties){
          if(!(Get-Member -inputobject $initobj -name $object_properties.Name -Membertype Properties)){
              if($debug){ write-host "adding property "$object_properties.Name}
              $initObj | Add-Member -MemberType NoteProperty -Name $object_properties.Name -Value $firstrow.($object_properties.Name)
          }
      }
  }
  clear-variable restemp -ErrorAction silent
  clear-variable resfinal -ErrorAction silent
  $restemp=@()
  $restemp+=$initobj
  if($debug){
    "added initobj:"
    $restemp
    "================="
  }
  foreach ($row in ($res| select -skip 1)){
      $restemp+=$row
  }
  if($restimedout1){
    foreach ($row in $restimedout1){
        $restemp+=$row
    }
  }
  if($restimedout2){
    foreach ($row in $restimedout2){
        $restemp+=$row
    }
  }
    
  if($appstatus.mode -eq "winrm"){
   $appstatus.lastresultdata=$restemp|Select-Object -Property * -ExcludeProperty PSComputerName,RunspaceId,PSShowComputerName
  }else{
   $appstatus.lastresultdata=$restemp
  }
  $appstatus.resultcount=($appstatus.lastresultdata|measure-object).count
  write-host "final count: "$appstatus.resultcount
  if($appstatus.resultcount -gt 30){
    write-host "showing first 30 results (all results are in CSV file):" -ForegroundColor cyan
  }else{
    write-host "showing first 30 results:" -ForegroundColor cyan
  }
  $res|select -first 30|ft -AutoSize
 if(!$appstatus.unattended -and ($action -eq "quickstatus" -or $action -eq "scanservers" -or $action -eq "diskspace" -or $action -eq "patchreport" -or $action -eq "getevents" -or $action -eq "servicecheck")){
    
      $toexport=read-host "export to CSV and HTML?"
 }else{
     $toexport="y"
 }
 if($toexport -like "y*" -or $toexport -like "z"){
     new-item -Name reports -ItemType directory -ErrorAction SilentlyContinue
     if($reportpath){
        $rpath=$reportpath
     }else{
        $rpath="reports\"
     }
     $appstatus.lastresultdata|export-csv ($rpath+$namecsv) -NoTypeInformation -delimiter ";"
     if(!$appstatus.unattended){notepad "reports\$namecsv"}
     if(!$appstatus.unattended -or $html -eq "yes"){
        #HTMLexportPatches   #too slow...
        HTMLexport
     }else{
        if(!$appstatus.unattended -or $html -eq "yes"){
            HTMLexport
        }
     }
     
 }
 if($appstatus.unattended){
   
   if($debug){read-host}
   break
 }
 if(test-path("c:\temp\TimedOutHostnames.txt")){
     write-host
     "some computers timed out and only partial info was included. You might want to run this again just on those"
     "(c:\temp\TimedOutHostnames.txt) and maybe they will go through next time (but probably not...)"
     notepad "c:\temp\TimedOutHostnames.txt"
 }
 if($totalcount -lt 50){ $resfinal|select hostname,online,ip,osshort,canonicalname|ft }
 read-host "press enter to continue..."
}  #end main cycle
