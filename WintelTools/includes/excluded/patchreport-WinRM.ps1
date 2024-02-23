$SBpatchreport_winrm={   #scriptblock

        $srname=$parameter.SRname
        $SAcredlist=$parameter.SAcredlist
        $csvlist=$parameter.csvlist
        #$kbs=$parameter.kbs
        #$dayshistory=$parameter.dayshistory
        $ip=$_
        $hn=$parameter.csvlist|where ip -eq $ip|select -expandproperty hostname
        write-host "$hn $ip"
$sess=get-pssession -name $ip -erroraction silentlycontinue
if(!$sess){
    if($sacredlist|where name -eq "$hn-$ip.xml"){   #checks for stand-alone credentials file
        write-host "$ip loading credentials "$env:appdata"\creds\sa\"$hn-$ip".xml"
        $sacreds=Import-CliXml -Path $env:appdata"\creds\sa\"$hn-$ip".xml"
        write-host "loaded :"$sacreds
        $sess=new-PSSession -ComputerName $ip -Credential $sacreds -errorvariable connerr
    }else{
        $sess=new-PSSession -ComputerName $ip -Credential $parameter.Credentials -errorvariable connerr
    }
    if(!$sess){
        $server = New-Object -TypeName psobject
        $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hn
        $server | Add-Member -MemberType NoteProperty -Name fqdn -Value ($parameter.csvlist|where ip -eq $ip|select -expandproperty fqdn)
        $server | Add-Member -MemberType NoteProperty -Name ip -Value $ip
        $server | Add-Member -MemberType NoteProperty -Name osshort -Value ($parameter.csvlist|where ip -eq $ip|select -expandproperty osshort)
        $server | Add-Member -MemberType NoteProperty -Name online -Value $false
        $server | Add-Member -MemberType NoteProperty -Name error -Value $connerr.errordetails.message
        $server
        return
    }
}


$res=invoke-command -session $sess -ScriptBlock {   #scriptblock 2
    Import-Module activedirectory -erroraction silentlycontinue
    $withevents=$true
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $env:computername
    $server | Add-Member -MemberType NoteProperty -Name ip -Value ""
    $server | Add-Member -MemberType NoteProperty -Name OSshort -value ""
    $server | Add-Member -MemberType NoteProperty -Name lastpatchdate -value ""
    $server | Add-Member -MemberType NoteProperty -Name lastboot -value ""
    $server | Add-Member -MemberType NoteProperty -Name WU_requiresReboot -value ""
    $server | Add-Member -MemberType NoteProperty -Name AUOptions -value ""
    $server | Add-Member -MemberType NoteProperty -Name lasteventmessage -value ""
    $server | Add-Member -MemberType NoteProperty -Name lasteventtime -value ""

        try{
            $wmi=Get-wmiobject win32_operatingsystem -ErrorAction SilentlyContinue #| select lastbootuptime,name
        }catch{
            #"$hostname error getting data"
            <#$dmz=$true
            $server.type="DMZ"
            $credential=getDMZcreds($hostname)
            $wmi=Get-wmiobject -cn $hostname -ClassName win32_operatingsystem -ErrorAction SilentlyContinue -credential $credential
            #>
        }
        if($wmi){
            $lb=$wmi.ConvertToDateTime($wmi.lastbootuptime)
            $server.lastboot=$lb
            if($server.osshort -eq ""){
                if($wmi.caption -like "*2016*"){ $server.OSshort="w2k16"}
                if($wmi.caption -like "*2012*"){ $server.OSshort="w2k12"}
                if($wmi.caption -like "*2008*"){ $server.OSshort="w2k8"}
                if($wmi.caption -like "*2003*"){ $server.OSshort="w2k3"}
            }
            write-host $server.hostname" "$server.OSshort" lastboot: $lb"
        }
    $reg1=Get-ItemProperty -path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\rebootrequired' -ErrorAction SilentlyContinue
    if($reg1){ $server.WU_requiresReboot=$true}
    $server.auoptions=(Get-ItemProperty -path 'Registry::HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU').auoptions
         $eventids=@(2,3,4)   #look for the last event when there was some installation
         if($withevents){

            $lastdate=Get-WinEvent -FilterHashTable @{LogName="setup"; id=$eventids}|select -expandproperty TimeCreated -first 1
            if(!$lastdate){
                $server.lastpatchdate=(Get-ItemProperty -path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install').lastsuccesstime
            }else{
                $server.lastpatchdate=$lastdate
                $lastdate=$lastdate.adddays(-1)  #include events from previous day in case patching happened through midnight
                $eventids=@(1,2,3,4)
                $kbsfound=get-hotfix |where {$_.installedon -ge $lastdate}
                $evts=Get-WinEvent -FilterHashTable @{LogName='setup'; StartTime=$lastdate;id=$eventids}|sort timecreated
                $evt=$evts|select -last 1
            }
            
            if($debug){$evts}

            if($evt){
                $server.lasteventmessage=$evt.message
                $server.lasteventtime=$evt.TimeCreated
            }<#else{    #this does not seem reliable
                try{
                    $r=New-Object System.Net.Sockets.TCPClient -ArgumentList "$($hostname)",3389
                    if($r){$server.rdp=$true}
                }catch{
                    $server.rdp=$false
                    #write-host " RDP error" -ForegroundColor red -NoNewline
                }
            }#>
         }
         $kbsfound=@()
            foreach($evt in $evts){
                $kb=""
                $pos=0
                if($evt.message -like "*successfully changed to the Installed*"){ $pos=1}
                if($evt.message -like "*reboot is necessary*"){$pos=6}
                if($evt.message -like "*Target state is Installed*"){$pos=4}
                if($evt.message -like "*failed to be changed to the Installed*"){$pos=1}
                if($pos){ $kb=(($evt.message.split())[$pos]).trim(".")}
                if($kb -gt 0){
                 if(!(Get-Member -inputobject $server -name $kb -Membertype Properties)){
                    $server | Add-Member -MemberType NoteProperty -Name $kb -value ""
                    $server | Add-Member -MemberType NoteProperty -Name ($kb+"_event") -value ""
                 }
                }
            }

            foreach($evt in $evts){
    if($evt.message -like "*successfully changed to the Installed*"){
        $kb=($evt.message.split())[1]
        #if(!(Get-Member -inputobject $server -name $kb -Membertype Properties))
        $server.($kb)=$true
        $server.($kb+"_event")="installed"
        #$server | Add-Member -MemberType NoteProperty -Name ($kb+"_event") -value "installed" -force
    }
    if($evt.message -like "*reboot is necessary*"){
        $kb=($evt.message.split())[6]
        $server.($kb+"_event")="reboot necessary"
    }
    if($evt.message -like "*Target state is Installed*"){
        $kb=(($evt.message.split())[4]).trim(".")
        $server.($kb+"_event")="initiating"
    }
    if($evt.message -like "*failed to be changed to the Installed*"){
        $kb=($evt.message.split())[1]
        $server.($kb+"_event")="failed"
    }
    if(!($kbsfound.contains($kb))){ $kbsfound+=$kb}
    if($kbsfound|where {$_.hotfixid -eq $kb}){ $server.($kb)=$true } #check KB install status from get-hotfix result regardless of eventlog
  

            

        }
    $server
}
$res.ip=$ip
$res
}