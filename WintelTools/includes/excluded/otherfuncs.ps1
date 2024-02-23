write-host "functions module 1.0.1.3" -ForegroundColor Green

$SBportcheck={
  Import-Module active*
  $SRname=$parameter.SRname
  $ports=$parameter.par
  $hostname=$_
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name online -value ""
  $server | Add-Member -MemberType NoteProperty -Name osshort -value ""
  $server | Add-Member -MemberType NoteProperty -Name ip -value ""
  if($srname){ $server | Add-Member -MemberType NoteProperty -Name SR -value $SRname}
    
  $props="operatingsystem"
  try{
   $ADobj=get-adcomputer $hostname -properties $props|select canonicalname, description, created,lastlogondate,operatingsystem
  }catch{}
  if($ADobj){
    $os=$ADobj.operatingsystem
    if($os -like "*2016*"){ $server.OSshort="w2k16"}
    if($os -like "*2012*"){
        if($os -like "*R2*"){
            $server.OSshort="w2k12r2"
        }else{
            $server.OSshort="w2k12"
        }
    }
    if($os -like "*2008*"){ $server.OSshort="w2k8"}
    if($os -like "*2003*"){ $server.OSshort="w2k3"}
  }
  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
  if(!$rtn){
    $server.online=$false
    write-host "$hostname offline" -ForegroundColor red;
  }else{
    $server.online=$true
    $server.IP=(($rtn.properties|where {$_.name -eq "ProtocolAddress"}).value|select -first 1)
    if(!$server.IP -or $server.ip -like "*::*"){ $server.IP=($rtn|select -first 1|select IPV4Address).IPV4Address.IPAddressToString }
    if($server.ip -eq "::1"){    #get ip of local host (a crazy way ;-)
       $server.ip=Get-NetIpaddress | Where {$_.addressstate -EQ "preferred" -and $_.IPAddress.length -gt 3 -and $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "*:*"}|select -expandproperty IPAddress
    }

  }
  if($ports){
    $p=$ports -split ","
    $p|foreach{
        $server | Add-Member -MemberType NoteProperty -Name "TCP_$_" -value "closed"
        try{
            $r=New-Object System.Net.Sockets.TCPClient -ArgumentList "$($hostname)",$_
            if($r){$server.("TCP_$_")="open"}
        }catch{
            write-host " TCP_$_ closed" -ForegroundColor red -NoNewline
        }
    }
  }
  $server
}

$SBwinrmtest={
    $hostname=$_
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name ping -value $true
    $server | Add-Member -MemberType NoteProperty -Name winrm -value $false
    $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    if(!$rtn){
        $server.ping=$false
        #return $server   #some servers are not pinging but services can be checked anyway
    }
    $k=test-wsman $hostname
    if($k){ $server.winrm=$true}
    $server
}
$SBservicecheck={
    $hostname=$_
    $svc=$parameter.par
    $servicestoignore=$parameter.servicestoignore
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name ping -value $true
    $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    if(!$rtn){
        $server.ping=$false
        #return $server   #some servers are not pinging but services can be checked anyway
    }
    if($svc){
        $obj=Get-WmiObject Win32_Service -cn $hostname|where {$_.displayname -like $svc -or $_.name -like $svc}|select name,displayname,startmode,state
        foreach($s in $obj){
            $server| Add-Member -MemberType NoteProperty -Name ($s.name+" ("+$s.displayname+")") -value ($s.state+" - "+$s.startmode)
        }
    }else{
        $obj=Get-WmiObject Win32_Service -cn $hostname|where {$_.startmode -eq "auto" -and ($_.state -eq "stopped" -or $_.state -eq "starting")}|select name,displayname,startmode
        #if($obj){     $server.online=$true}   #this does not work?
        foreach($s in $obj){
            $n1=$s.name
            $n2=$s.displayname
            if(!($servicestoignore -like "*$n1*" -or $servicestoignore -like "*$n2*")){
                $server| Add-Member -MemberType NoteProperty -Name $s.name -value "stopped"
            }
        }
    }
    $server
}
$SBperfmon={
    $hostname=$_
    $counters=$parameter.par
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -value ""
    $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    if(!$rtn){
        $server.online=$false
        return $server
    }
    $server.online=$true
    
    $counters=($counters -split '\r?\n').Trim()
foreach($counter in $counters){
    #"\\$hostname"+$counter
    if(!$counter){ continue }  #skip empty line
     $list=Get-Counter ("\\$hostname"+$counter) | select -expand counter*
foreach($line in $list){
    $name=""
    if($line.path -like "*)*"){
        $p=$line.path.split("(")
        #$p
        $p1=$p[1].split(")")
        if($line.CookedValue -eq 0 -and $p1[0].length -gt 30){
            #too long and 0 valued = not interesting
        }else{
            $name=$p[1]
        }
    }else{
        $p=$line.path.split("\")
        $name=$p|select -last 1
    }
    if($name){
        $val=[math]::Round($line.cookedvalue)
        $server|add-member -MemberType NoteProperty -Name $name -value $val
    }
    
}
}
    $server
}

$SBcopyfiles_winRM={
        $SAcredlist=$parameter.SAcredlist
    $files=$parameter.files
    $destination=$parameter.destination
        #$kbs=$parameter.kbs
        #$dayshistory=$parameter.dayshistory
        $ip=$_

$sess=get-pssession -name $ip -erroraction silentlycontinue
if(!$sess){
    if($sacredlist|where name -eq "$ip.xml"){   #checks for stand-alone credentials file
        write-host "$ip loading credentials "$env:appdata"\creds\sa\"$ip".xml"
        $sacreds=Import-CliXml -Path $env:appdata"\creds\sa\"$ip".xml"
        $sess=new-PSSession -ComputerName $ip -Credential $sacreds -errorvariable connerr
    }else{
        $sess=new-PSSession -ComputerName $ip -Credential $parameter.Credentials -errorvariable connerr
    }
    if(!$sess){
        $server = New-Object -TypeName psobject
        $server | Add-Member -MemberType NoteProperty -Name ip -Value $ip
        $server | Add-Member -MemberType NoteProperty -Name online -Value $false
        $server | Add-Member -MemberType NoteProperty -Name error -Value $connerr.errordetails.message
        $server
        return
    }
}
copy-item -LiteralPath "c:\ibm\WUtools\*" -destination c:\temp -fromsession $sess
copy-item -LiteralPath "c:\ibm\WUtools\*" -destination "c:\temp\$ip\" -fromsession $sess
}

$SBcopyfiles={
    $hostname=$_
    $files=$parameter.files
    $destination=$parameter.destination
    $debug=$false
    if($debug){
        $hostname="cnosv0279ws0021" #dmz
        #$hostname="cdksvno0279ap52"
    }
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -value ""
    $server | Add-Member -MemberType NoteProperty -Name status -value ""
    $server | Add-Member -MemberType NoteProperty -Name type -value "domain"
    $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    if(!$rtn){
        $server.online=$false
        $server.status="error"
        $server.type=""
        return $server
    }
        $server.online=$true
            if(!(test-path "\\$hostname\c$")){
                $server.type="SA"
                $server.status="access denied"
            }else{
                #not SA
                #foreach($path in $paths){   #maybe make this later
                    #copy-item $path $destination
                    #if(!(test-path("\\$hostname\$destination"))){ new-item "\\$hostname\$destination" -ItemType directory
                    xcopy $files ("\\$hostname\"+$destination) /Y /e /i /s
                    if($?){
                        $server.status="done"
                    }else{
                        $server.status="error?"
                    }
                #}
            }
        
        <#if($server.type -eq "SA"){
            if($debug){ "stand-alone copying" }
            $drivename=($hostname+"_C")
            $r=new-psdrive -name $drivename -PSProvider "FileSystem" -root "\\$hostname\c$" -credential $credential
            copy-item ($drivename+":\scripts\WUtools\*.txt") \\fp2svno0279fs01\media$\WUpdateLogs\DMZ\ -force
            copy-item ($drivename+":\scripts\WUtools\currentstate\*.txt") \\fp2svno0279fs01\media$\WUpdateLogs\DMZ\currentstate\ -force
            remove-psdrive $drivename
        }#>
    $server
}
$SBfilecheck={
    $hostname=$_
    $files=$parameter.files
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -value ""
    $server | Add-Member -MemberType NoteProperty -Name type -value "domain"
    $server | Add-Member -MemberType NoteProperty -Name status -value ""
    $server | Add-Member -MemberType NoteProperty -Name filepresent -value ""
    $server | Add-Member -MemberType NoteProperty -Name fileversion -value ""
    $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    if(!$rtn){
        $server.online=$false
        $server.status="error"
        $server.type=""
        return $server
    }
        $server.online=$true
            if(!(test-path "\\$hostname\c$")){
                $server.type="SA"
                $server.status="access denied"
            }else{
                #not SA
                #foreach($path in $paths){   #maybe make this later
                $server.filepresent=test-path("\\$hostname\"+$files)
                $server.fileversion=(Get-Item ("\\$hostname\"+$files)).VersionInfo.FileVersion

            }
    $server
}

$SBpatchreportKBs={ 
$kbs=$parameter.par
$hostname=$_
write-host " $hostname"
$arr=$kbs -split ","
$data=@()
$rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
if(!$rtn){
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -Value $false
    $server
}
foreach($kb in $arr){
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    if(!($kb -like "kb*")){ $kb="kb$kb"}
    $server | Add-Member -MemberType NoteProperty -Name updatekb -Value $kb
    write-host " get-hotfix -cn $hostname $kb"
    $state=get-hotfix -cn $hostname $kb
    if($state){
        $server | Add-Member -MemberType NoteProperty -Name state -value $true
    }else{
        $server | Add-Member -MemberType NoteProperty -Name state -value $false
    }
    $data+=$server
}
return $data
}

$SBpatchreportall={ 
$hostname=$_
write-host " $hostname"
$data=@()
$rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
if(!$rtn){
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -Value $false
    $server
}
$kbs=get-hotfix -cn $hostname
foreach($kb in $kbs){
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name HotFixID -Value $kb.HotFixID
    $data+=$server
}
return $data
}

$SBpatchreportall2={ 
$hostname=$_
write-host " $hostname"
$server = New-Object -TypeName psobject
$server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
$server | Add-Member -MemberType NoteProperty -Name online -Value $true
$server | Add-Member -MemberType NoteProperty -Name osshort -Value $true
$props="operatingsystem"
    $ADobj=get-adcomputer $hostname -properties $props|select operatingsystem
    if($ADobj){
        $server | Add-Member -MemberType NoteProperty -Name OS -value $ADobj.operatingsystem
        if($ADobj.operatingsystem -like "*2019*"){ $server.OSshort="w2k19"}
        if($ADobj.operatingsystem -like "*2016*"){ $server.OSshort="w2k16"}
        if($ADobj.operatingsystem -like "*2012*"){
            if($ADobj.operatingsystem -like "*R2*"){
                $server.OSshort="w2k12r2"
            }else{
                $server.OSshort="w2k12"
            }
        }
        if($ADobj.operatingsystem -like "*2008*"){ $server.OSshort="w2k8"}
        if($ADobj.operatingsystem -like "*2003*"){ $server.OSshort="w2k3"}
    }

$rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
if(!$rtn){
    $server.online=$false
}
$kbs=get-hotfix -cn $hostname
if(!$kbs){
    return $server
}
$kbs=get-hotfix -cn $hostname
foreach($kb in $kbs){
    $server | Add-Member -MemberType NoteProperty -Name $kb.HotFixID -value $true
}
return $server
}

$SBpatchreport={ 
    Import-Module activedirectory -erroraction silentlycontinue
    $debug=$false
    if($debug){
        $hostname = "cdksvno0279ws02"
        $withevents=$false
        $withkbs=$false
    }else{
        $srname=$parameter.SRname
        #$kbs=$parameter.kbs
        $withevents=$parameter.withevents
        $withkbs=$parameter.withkbs
        #$dayshistory=$parameter.dayshistory
        $hostname=$_
    }
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -value ""
    $server | Add-Member -MemberType NoteProperty -Name OSshort -value ""
    $server | Add-Member -MemberType NoteProperty -Name type -value "AD"
    $server | Add-Member -MemberType NoteProperty -Name lastpatchdate -value ""
    $server | Add-Member -MemberType NoteProperty -Name lastboot -value ""
    $server | Add-Member -MemberType NoteProperty -Name AUOptions -value ""
    $server | Add-Member -MemberType NoteProperty -Name WSUSserver -value ""
    $server | Add-Member -MemberType NoteProperty -Name TargetGroup -value ""
    $server | Add-Member -MemberType NoteProperty -Name WU_requiresReboot -value ""
    $server | Add-Member -MemberType NoteProperty -Name lasteventmessage -value ""
    $server | Add-Member -MemberType NoteProperty -Name lasteventtime -value ""
    $props="canonicalname","description","created","ServicePrincipalName","lastlogondate","operatingsystem"
    $ADobj=get-adcomputer $hostname -properties $props|select operatingsystem
    if($ADobj){
        $server | Add-Member -MemberType NoteProperty -Name OS -value $ADobj.operatingsystem
        if($ADobj.operatingsystem -like "*2019*"){ $server.OSshort="w2k19"}
        if($ADobj.operatingsystem -like "*2016*"){ $server.OSshort="w2k16"}
        if($ADobj.operatingsystem -like "*2012*"){
            if($ADobj.operatingsystem -like "*R2*"){
                $server.OSshort="w2k12r2"
            }else{
                $server.OSshort="w2k12"
            }
        }
        if($ADobj.operatingsystem -like "*2008*"){ $server.OSshort="w2k8"}
        if($ADobj.operatingsystem -like "*2003*"){ $server.OSshort="w2k3"}
    }
    $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
    if(!$rtn){
        $server.online=$false
    }else{
        $server.online=$true
    }
    
        $dmz=$false
        try{
            $wmi=Get-wmiobject -cn $hostname -ClassName win32_operatingsystem -ErrorAction SilentlyContinue #| select lastbootuptime,name
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
        }
        <#else{if($server.type -eq "DMZ"){
            $RegCon = Get-WmiObject -List -Namespace root\default -ComputerName $hostname -Credential $credential | Where-Object {$_.Name -eq "StdRegProv"}
        }#>
        try{$RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$hostname)}catch{}
        
        
        if($RegCon){
            $server.online=$true
            $RegWUAU = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	        $RegWUAURebootReq = $RegWUAU.GetSubKeyNames() 
	        $WUAURebootReq = $RegWUAURebootReq -contains "RebootRequired"
            $server.WU_requiresReboot=$WUAURebootReq
            $Regkey = $RegCon.OpenSubKey("Software\Policies\Microsoft\Windows\WindowsUpdate")
            if($regkey){
                if($server|gm -name WSUSserver){$server.WSUSserver=$RegKey.GetValue("WUServer")}
                if($server|gm -name TargetGroup){$server.TargetGroup=$RegKey.GetValue("TargetGroup")}
            }
            $Regkey = $RegCon.OpenSubKey("Software\Policies\Microsoft\Windows\WindowsUpdate\AU")
            if($regkey){
               $server.AUOptions=$RegKey.GetValue("AUOptions")
            }
        }
         #KBs
         $eventids=@(2,3,4)   #look for the last event when there was some installation
         if($withevents){
            <#if($dmz){
                $evts=Get-WinEvent -cn $hostname -credential $credential -FilterHashTable @{LogName='setup'; StartTime=$datefrom;id=$eventids}|sort timecreated
            }else{#>
              $getevent=$true
              $lastdate=Get-WinEvent -cn $hostname -FilterHashTable @{LogName="setup"; id=$eventids}|select -expandproperty TimeCreated -first 1
              if(!$lastdate){
                $lastdate=invoke-command -cn $hostname -argumentlist $eventids {param($eventids); get-winevent -FilterHashTable @{LogName="setup"; id=$eventids}|select -expandproperty TimeCreated -first 1}
                $getevent=$false
              }
              $server.lastpatchdate=$lastdate
              $lastdate=$lastdate.adddays(-1)  #include events from previous day in case patching happened through midnight
              $eventids=@(1,2,3,4)
              $kbsfound=get-hotfix -cn $hostname |where {$_.installedon -ge $lastdate}
              if($getevent){
                $evts=Get-WinEvent -cn $hostname -FilterHashTable @{LogName='setup'; StartTime=$lastdate;id=$eventids}|sort timecreated
              }else{
                $evts=invoke-command -cn $hostname -argumentlist $lastdate,$eventids -scriptblock {
                    param($lastdate,$eventids)
                    $lastdate
                    $eventids

                    Get-WinEvent -FilterHashTable @{LogName='setup'; StartTime=$lastdate;id=$eventids}|sort timecreated
                    Get-WinEvent -FilterHashTable @{LogName='setup'; StartTime=$lastdate}|sort timecreated
                }
              }
            #}
            $evt=$evts|select -last 1
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
                    #write-host " RDP error " -ForegroundColor red -NoNewline
                }
            }#>
         }
         $kbsfound=@()
         if($withkbs){
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
                 }
                }
            }

            foreach($evt in $evts){
    if($evt.message -like "*successfully changed to the Installed*"){
        $kb=($evt.message.split())[1]
        #if(!(Get-Member -inputobject $server -name $kb -Membertype Properties))
        $server.($kb)=$true
    }
    if($evt.message -like "*reboot is necessary*"){
        $kb=($evt.message.split())[6]
        $server.($kb)="reboot necessary"
    }
    if($evt.message -like "*Target state is Installed*"){
        $kb=(($evt.message.split())[4]).trim(".")
        $server.($kb)="initiating"
    }
    if($evt.message -like "*failed to be changed to the Installed*"){
        $kb=($evt.message.split())[1]
        $server.($kb)="failed"
    }
    if(!($kbsfound.contains($kb))){ $kbsfound+=$kb}
    if($kbsfound|where {$_.hotfixid -eq $kb}){ $server.($kb)=$true } #check KB install status from get-hotfix result regardless of eventlog
  

            

        }
    }
    $server
}

$SBtsm={
    $hostname=$_
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -value ""
    #work in progress
}

$SBdiskspace={

    $SRname=$parameter.SRname
    $hostname=$_
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $server | Add-Member -MemberType NoteProperty -Name online -value ""

  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
  if(!$rtn){
    $server.online=$false
    write-host "$hostname offline" -ForegroundColor red;
  }else{
    $server.online=$true
    $dmz=$false
    try{
        $wmi=Get-wmiobject win32_operatingsystem -cn $hostname -ErrorAction SilentlyContinue #| select lastbootuptime,name
    }catch{
        #"$hostname error getting data"
        $dmz=$true
        $credential=getDMZcreds($hostname)
        $wmi=Get-wmiobject win32_operatingsystem -cn $hostname -ErrorAction SilentlyContinue -credential $credential
    }

    if(!$wmi){
        write-host "$hostname WMI error" -ForegroundColor DarkYellow;
        $wmiok=$false
    }else{
        $server | Add-Member -MemberType NoteProperty -Name OS -value ""
        $server | Add-Member -MemberType NoteProperty -Name OSshort -value ""

        $server.OS=$wmi.caption
        if($wmi.name -like "*2016*"){ $server.OSshort="w2k16"}
        if($wmi.name -like "*2012*"){ $server.OSshort="w2k12"}
        if($wmi.name -like "*2008*"){ $server.OSshort="w2k8"}
        if($wmi.name -like "*2003*"){ $server.OSshort="w2k3"}

        if($dmz){
            $logical = Get-WMIObject Win32_LogicalDisk -filter "DriveType=3" -ComputerName $hostname -erroraction silentlycontinue -credential $credential
        }else{
            $logical = Get-WMIObject Win32_LogicalDisk -filter "DriveType=3" -ComputerName $hostname -erroraction silentlycontinue
        }
        foreach ($log in $logical){
            $name=($log.name).TrimEnd(":")
	   	    $server | add-member noteproperty ("$name"+"_freespace") (($log.freespace)/1GB).tostring(".00")
            $server | add-member noteproperty ("$name"+"_capacity") (($log.size)/1GB).tostring(".00")
            $server | add-member noteproperty ("$name"+"_percFree") ([math]::round(($log.freespace/$log.size)*100))
        }
    }
    $server
  }
}

#[System.Collections.ArrayList]$servers = @()


$SBWUreg={
  Import-Module active*
  $hostname=$_
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name online -value ""
  $server | Add-Member -MemberType NoteProperty -Name osshort -value ""
  $server | Add-Member -MemberType NoteProperty -Name lastWUdetectResult -value ""
  $server | Add-Member -MemberType NoteProperty -Name LastSuccessTime1 -value ""
  $server | Add-Member -MemberType NoteProperty -Name lastWUdownloadResult -value ""
  $server | Add-Member -MemberType NoteProperty -Name LastSuccessTime2 -value ""
  $server | Add-Member -MemberType NoteProperty -Name lastWUinstallResult -value ""
  $server | Add-Member -MemberType NoteProperty -Name LastSuccessTime3 -value ""
  $server | Add-Member -MemberType NoteProperty -Name WU_requiresReboot -value ""
  if($srname){ $server | Add-Member -MemberType NoteProperty -Name SR -value $SRname}
  $props="canonicalname","description","created","lastlogondate","operatingsystem"
  $ADobj=get-adcomputer $hostname -properties $props|select canonicalname, description, created,lastlogondate,operatingsystem
  if($ADobj){
    $server | Add-Member -MemberType NoteProperty -Name OS -value $ADobj.operatingsystem
    if($ADobj.operatingsystem -like "*2016*"){ $server.OSshort="w2k16"}
    if($ADobj.operatingsystem -like "*2012*"){ $server.OSshort="w2k12"}
    if($ADobj.operatingsystem -like "*2008*"){ $server.OSshort="w2k8"}
    if($ADobj.operatingsystem -like "*2003*"){ $server.OSshort="w2k3"}
    $server | Add-Member -MemberType NoteProperty -Name lastlogondate -value $ADobj.lastlogondate
    $server | Add-Member -MemberType NoteProperty -Name canonicalname -value $ADobj.canonicalname
    $server | Add-Member -MemberType NoteProperty -Name description -value $ADobj.description
    $server | Add-Member -MemberType NoteProperty -Name created -value $ADobj.created
  }
  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
  if(!$rtn){
    $server.online=$false
    write-host "$hostname offline" -ForegroundColor red;
  }

    try{$RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$hostname)}catch{}
    if($RegCon){
            $server.online=$true
            $RegWUAU = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	        $RegWUAURebootReq = $RegWUAU.GetSubKeyNames() 
	        $WUAURebootReq = $RegWUAURebootReq -contains "RebootRequired"
            $server.WU_requiresReboot=$WUAURebootReq
            if($server.os -like "*2016*"){
                $evt=Get-WinEvent -cn $hostname -LogName Microsoft-Windows-WindowsUpdateClient/Operational | where{$_.Id -match "26"} | select -First 1
                $server.LastSuccessTime1=$evt.timecreated
                if($evt.message -like "*0 updates*"){
                    $server.lastWUdetectResult=0
                }else{
                    $server.lastWUdetectResult=$evt.message
                }
            }else{
            
                $Regkey = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect")
                if($regkey){
                    $server.lastWUdetectResult='{0:x}' -f $RegKey.GetValue("LastError")
                    $server.LastSuccessTime1=$RegKey.GetValue("LastSuccessTime")
                }
            
                $Regkey = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download")
                if($regkey){
                    $server.lastWUdownloadResult='{0:x}' -f $RegKey.GetValue("LastError")
                    $server.LastSuccessTime2=$RegKey.GetValue("LastSuccessTime")
                }
                $Regkey = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install")
                if($regkey){
                    $server.lastWUinstallResult='{0:x}' -f $RegKey.GetValue("LastError")
                    $server.LastSuccessTime3=$RegKey.GetValue("LastSuccessTime")
                }
            }
        
    }
  $server
}

#unused script - might be used later
$SBreboots={
    $hostname=$_
    $server = New-Object -TypeName psobject
    $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
    $choice=$parameter.par
    write-host "par: $choice"
    write-host "hostname: $hostname"

       $i = 0 
        $RecentShutdowns = 0 
        $RecentUnexpected = 0 
         
        $BootHistory = @() 
        $ShutdownDetail = @() 
        $UnexpectedShutdowns = @()  
         
        # Store original credential, if we attempt to make a local connection we need to  
        # temporarily empty out the credential object. 
        $Original_Credential = $Credential 
         
        # Select properties defined to ensure proper display order. 
             "choice $choice"
        if($choice -eq 1){
             "choiceIN $choice"
          $server | Add-Member -MemberType NoteProperty -Name BootHistory -value "1"
          $server | Add-Member -MemberType NoteProperty -Name LastShutdownUser -value "1"
          $BootInformation = @( 
            "Computer" 
            "BootHistory" 
            "LastShutdownUser" 
          )
          }else{
           $BootInformation = @( 
            "Computer" 
            "BootHistory" 
            "RecentShutdowns" 
            "UnexpectedShutdowns" 
            "RecentUnexpected" 
            "PercentDirty" 
            "LastShutdown" 
            "LastShutdownType" 
            "LastShutdownUser" 
            "LastShutdownProcess" 
            "LastShutdownReason" 
          ) 
         }
        # Arguments to be passed to our WMI call.  
        $Params = @{ 
            ErrorAction        = 'Stop' 
            ComputerName    = $Computer 
            Credential        = $Credential 
            Class            = 'Win32_NTLogEvent' 
            Filter            = "LogFile = 'System' and EventCode = 6009 or EventCode = 6008 or EventCode = 1074" 
        } 
    

     "choice $choice"
            $Params.ComputerName = $hostname 
             
            # You can't use credentials when connecting to the local machine so temporarily empty out the credential object. 
            If ($Computer -eq $Env:ComputerName) {  
                $Params.Credential = [System.Management.Automation.PSCredential]::Empty 
            } 
             
            Try {  
                $d = 0 
                $Events = Get-WmiObject @Params |select -first 4
                ForEach ($Event In $Events) {  
                 
                    Write-Progress -Id 2 -ParentId 1 -Activity "Processing reboot history." -PercentComplete (($d / $Events.Count)*100); $d++ 
                     
                    # Record the relevant details for the shutdown event. 
                    Switch ($Event.EventCode) {  
                        6009 { $BootHistory += (Get-Date(([WMI]'').ConvertToDateTime($Event.TimeGenerated)) -Format g) } 
                        6008 { $UnexpectedShutdowns += ('{0} {1}' -f ($Event.InsertionStrings[1], $Event.InsertionStrings[0])) } 
                        1074 { $ShutdownDetail += $Event } 
                    } 
                } 
                 
                # We explicitly ignore exceptions originating from this process since some versions of Windows may store dates in invalid formats (e.g. ?11/?16/?2014) in the event log after an unexpected shutdown causing this calculation to fail. 
                Try {  
                    $RecentUnexpected = ($UnexpectedShutdowns | ? { ((Get-Date)-(Get-Date $_)).TotalDays -le 30 }).Count 
                } Catch {  
                    $RecentUnexpected = "Unable to calculate." 
                }  
                 
                # Grab details about the last clean shutdown and generate our return object. 
                $ShutdownDetail | Select -First 1 | ForEach-Object {  
                    if($choice -eq 1){
                     
                        $server.BootHistory = $BootHistory  
                        $server.LastShutdownUser = $_.InsertionStrings[6] 
                     
                    }else{
                        $server.BootHistory = $BootHistory  
                        $server.LastShutdownUser = $_.InsertionStrings[6] 
                        
                         $server | Add-Member -MemberType NoteProperty -Name RecentUnexpected -value $RecentUnexpected 
 
                         $server | Add-Member -MemberType NoteProperty -Name UnexpectedShutdowns -value $UnexpectedShutdowns 
                         $server | Add-Member -MemberType NoteProperty -Name LastShutdownProcess -value $_.InsertionStrings[0] 
                         $server | Add-Member -MemberType NoteProperty -Name PercentDirty -value '{0:P0}' -f (($UnexpectedShutdowns.Count/$BootHistory.Count)) 
                         $server | Add-Member -MemberType NoteProperty -Name LastShutdownType -value (Get-Culture).TextInfo.ToTitleCase($_.InsertionStrings[4]) 
                         $server | Add-Member -MemberType NoteProperty -Name LastShutdown -value (Get-Date(([WMI]'').ConvertToDateTime($_.TimeGenerated)) -Format g) 
                         $server | Add-Member -MemberType NoteProperty -Name RecentShutdowns -value ($BootHistory | ? { ((Get-Date)-(Get-Date $_)).TotalDays -le 30 }).Count 
                         $server | Add-Member -MemberType NoteProperty -Name LastShutdownReason -value 'Reason Code: {0}, Reason: {1}' -f ($_.InsertionStrings[3], $_.InsertionStrings[2]) 
                        
                     
                    }
                }             
            } Catch [System.Exception] { 
                # We explicitly ignore exceptions originating from Get-Date since some versions of Windows may store dates in invalid formats in the event log after an unexpected shutdown. 
                If ($_.CategoryInfo.Activity -ne 'Get-Date') {  
                    Write-Warning ("Unable to retrieve boot history for {0}. `nError Details: {1}" -f ($Computer, $_)) 
                } 
            } 
             
            # Reset credential object since we may have temporarily overwrote it to deal with local connections. 
            $Params.Credential = $Original_Credential 
        
    
    $server
}
