
$global:appstatus=[pscustomobject] @{
    online=$false
    eventcount=0
    linesTodisplay=30
    lasteventtime=""
    hostname=""
    logname=""
    source=""
    level=""
    days=0
    page=1
    pagecount=1
    datefrom=""
    eventids=""
    avgchangefreq=1
    readfrequency=1
    changed=$false
    state="watching"
    mode="c"
    string=""
    wrap=$false
    events=@()
    displayedresults=@()
}

$fileversion="1.0.0.0"

function rewrite(){
clear-host
write-host "============================================================================================"
write-host "Event Viewer $fileversion " -ForegroundColor magenta -nonewline
write-host ($appstatus.state)"$filename " -ForegroundColor cyan -NoNewline
if($appstatus.online){
    write-host "online:"($appstatus.online)" page:"$appstatus.page"of"$appstatus.pagecount
}else{
    write-host "online:"($appstatus.online) -ForegroundColor red
}
if($appstatus.online){
    write-host "last event:"($appstatus.lasteventtime) -NoNewline
    write-host " | eventcount:"($appstatus.eventcount) -NoNewline
    write-host " | check frequency:"($appstatus.readfrequency)"s" -NoNewline
    if($appstatus.mode -eq "s"){
        write-host
        write-host "string filter: "$appstatus.string
    }else{
        write-host " | events to display:"($appstatus.linesTodisplay)
    }
}
write-host "controls: " -nonewline
write-host "P pause, S settings, scroll PgUp/PgDn, E expand values, X export data, Q quit" -ForegroundColor cyan
write-host "============================================================================================"
if($appstatus.events){
    $result=$appstatus.events|select -last ($appstatus.linesTodisplay*$appstatus.page)|select -first $appstatus.linesTodisplay
    if($appstatus.wrap){
        $result|ft -autosize -Wrap
    }else{
        $result|ft -autosize 
    }
    $appstatus.displayedresults=$result

}
}

function getevents(){
    write-host "getting events..."
    $starttime=(get-date)
    if($appstatus.string -eq ""){$filter="*"}else{$filter="*"+$appstatus.string+"*"}
    $hashtable=@{"logname"=$appstatus.logname}
    if($appstatus.eventids){$hashtable.add("id",$appstatus.eventids)}
    if($appstatus.source){$hashtable.add("providername",$appstatus.source)}
    if($appstatus.level){$hashtable.add("level",$appstatus.level)}
    if($appstatus.datefrom){$hashtable.add("StartTime",$appstatus.datefrom)}
    #$hashtable
    #read-host "debug"
    #$appstatus
    if($appstatus.string){
        $filter="*"+$appstatus.string+"*"
        $appstatus.events=Get-WinEvent -cn $appstatus.hostname -FilterHashTable $hashtable|where {$_.message -like $filter}|select TimeCreated,Id,LevelDisplayName,ProviderName,Message
    }else{
        $appstatus.events=Get-WinEvent -cn $appstatus.hostname -FilterHashTable $hashtable|select TimeCreated,Id,LevelDisplayName,ProviderName,Message
    }
    #$appstatus.events=Get-WinEvent -cn $appstatus.hostname -FilterHashTable @{LogName=$appstatus.logname; id=$appstatus.eventids; StartTime=$appstatus.datefrom}|where {$_.message -like $filter}|select TimeCreated,Id,LevelDisplayName,ProviderName,Message
    
    $appstatus.eventcount=($appstatus.events|measure-object|select -expandproperty count)
    $appstatus.pagecount=[math]::round($appstatus.eventcount/$appstatus.linestodisplay)
    #write-host "count:"($appstatus.events|measure-object|select -expandproperty count)
    $stoptime=(get-date)
    $sec=($stoptime-$starttime).seconds
    if($sec -gt $appstatus.readfrequency){ $appstatus.readfrequency=$sec}  #decreasing read frequency to lower disk/network load

}
function checkfornew(){
    #write-host "checkfornew"
    $starttime=(get-date)
    if($appstatus.string -eq ""){$filter="*"}else{$filter="*"+$appstatus.string+"*"}
    if($appstatus.eventids -eq ""){
        $evt=Get-WinEvent -cn $appstatus.hostname -FilterHashTable @{LogName=$appstatus.logname; StartTime=$appstatus.datefrom}|where {$_.message -like $filter}|select TimeCreated,Id,LevelDisplayName,ProviderName,Message|select -first 1
    }else{
        $evt=Get-WinEvent -cn $appstatus.hostname -FilterHashTable @{LogName=$appstatus.logname; id=$appstatus.eventids; StartTime=$appstatus.datefrom}|where {$_.message -like $filter}|select TimeCreated,Id,LevelDisplayName,ProviderName,Message|select -first 1
    }
    #write-host "evt:"$evt
    #write-host "timecreated:"$evt.TimeCreated -NoNewline
    #write-host (!($appstatus.lasteventtime -eq $evt.TimeCreated))
    if(!($appstatus.lasteventtime -eq $evt.TimeCreated)){
        $appstatus.changed=$true
        $appstatus.lasteventtime=$evt.TimeCreated

    }else{
        $appstatus.changed=$false
    }
}
function settings(){
    write-host "EventLog viewer settings" -ForegroundColor cyan
    write-host "current:"
    write-host "host: "$appstatus.hostname
    write-host "logname: "$appstatus.logname
    write-host "source: "$appstatus.source
    write-host "level: "$appstatus.level
    write-host "eventids: "$appstatus.eventids
    write-host "datefrom: "$appstatus.datefrom
    $hostname=read-host "enter hostname or leave empty for localhost"
    if($hostname -eq ""){$hostname="localhost"}
    $logname=""
    while($logname -eq ""){
        $logname=read-host "enter logname (eg. application/setup/system)"
    }
    write-host "4 - Informational"
    write-host "3 - Warning"
    write-host "2 - Error"
    write-host "1 - Critical"
    $level=read-host "choose level number (leave empty for any)"
    $eventids=read-host "enter eventids (numbers separated by ,) or leave empty for any"
    $source=read-host "enter source (providername) or leave blank for any"
    
    while(!$inputOK){
        $p=read-host "enter how many days into past to search (leave blank for default 1)"
        if($p -ne ""){
            try{$p=[int]$p; $inputOK=$true; $days=$p}catch{$inputOK=$false}
        }else{
            $days=1
            $inputOK=$true
        }
    }
    $appstatus.hostname=$hostname
    $appstatus.logname=$logname
    $appstatus.source=$source
    $appstatus.level=$level
    $appstatus.eventids=$eventids
    $appstatus.days=$days
    $appstatus.datefrom=(get-date).adddays(-$days)
    $appstatus.string=read-host "enter filter string (leave blank for no string filtering)"
    $inputOK=$false
    while(!$inputOK){
        $p=read-host "number of lines to display (leave blank for default 30)"
        if($p -ne ""){
            try{$p=[int]$p; $inputOK=$true; $appstatus.linestodisplay=$p}catch{$inputOK=$false}
        }else{
            $appstatus.linestodisplay=30
            $inputOK=$true
        }
    }
}
function testconn(){
    $rtn=test-connection $appstatus.hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    write-host $rtn
    if(!$rtn){      #Why the heck is $rtn false even when it pings?!
        $appstatus.online=$false
        write-host "offline"
    }
}

$global:run=1
$c=0
$refresh=$false
settings
<#
#DEBUG
$appstatus.hostname="localhost"
$appstatus.logname="system"
$appstatus.eventids=""
$appstatus.days=1
$appstatus.datefrom=(get-date).adddays(-$appstatus.days)
write-host "datefrom:"$appstatus.datefrom
#DEBUG
#>
if($appstatus.hostname -eq "localhost"){
    $appstatus.online=$true
}else{
    #write-host "checking connection to "$appstatus.hostname
    testconn    
    $appstatus.online=$true   #check does not work so I set it to online
    #read-host "debug "$appstatus.online
}
#getevents
#read-host "debug"
rewrite

while($run){
    #write-host "$c datefrom:"$appstatus.datefrom" online:" $appstatus.online" changed:"$appstatus.changed" refresh:$refresh"
    if($c % 10 -eq 0 -and ($appstatus.offline)){
        write-host "checking connection to "$appstatus.hostname
        testconn
    }
    if($c % 2 -eq 0 -and ($appstatus.online) -and $appstatus.state -eq "watching"){   #file not found
        checkfornew
    }
    if(($c % $appstatus.readfrequency) -eq 0 -and $appstatus.online -and $appstatus.changed){
        getevents
        $appstatus.changed=$false
        $refresh=$true
    }
        
    if ([Console]::KeyAvailable){
        $keyInfo = [Console]::ReadKey($true)
        write-host "key:"$keyInfo.key
        if($keyInfo.key -eq "p"){
            if($appstatus.state -eq "watching"){
                $appstatus.state="PAUSED"
                $refresh=$true
            }else{
                $appstatus.state="watching"
                $refresh=$true
            }
        }
        if($keyInfo.key -eq "e"){
            if($appstatus.wrap){
                $appstatus.wrap=$fase
            }else{
                $appstatus.wrap=$true
            }
            $appstatus.changed=$true
            $c=0
        }
        if($keyInfo.key -eq "x"){
            write-host "a - export all "$appstatus.eventcount" fetched results"
            write-host "d - export only what is display"
            $q=read-host "choose"
            $fn=$appstatus.hostname+"-"+$appstatus.logname+"-events.csv"
            if($q -eq "a"){
                $appstatus.events|export-csv $fn -NoTypeInformation
            }
            if($q -eq "d"){
                $appstatus.displayedresults|export-csv $fn -NoTypeInformation
            }
            write-host "exported to $fn"

        }
        if($keyInfo.key -eq "s"){
            #write-host "refresh: $refresh"
            settings
            write-host "settings saved"
            #write-host "refresh: $refresh"
            #start-sleep 1
            $appstatus.changed=$true
            $c=0
        }
        if($keyInfo.key -eq "q"){
            $run=0
        }
        if($keyInfo.key -eq "PageDown"){
            #write-host "PageDown"
            if($appstatus.page -gt 1){
                    $appstatus.page=$appstatus.page-1
                    $refresh=$true
            }
        }
        if($keyInfo.key -eq "PageUp"){
            #write-host "PageUp"
            if($appstatus.page -gt 0){
                $v=$appstatus.page*$appstatus.linestodisplay
                #write-host "v: $v"
                if($v -le $appstatus.eventcount){
                    $appstatus.page=$appstatus.page+1
                    $refresh=$true
                }
            }
        }
        #read-host "debug"
    }
        if($refresh){
            #read-host "rewriting..."
            rewrite
            $refresh=$false
        }
    if(!$appstatus.changed){ start-sleep -Milliseconds 100}
    $c++
    if($c -gt 1023){$c=0}
}