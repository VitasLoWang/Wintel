#this is an include file for WintelTools.ps1

write-host "inventory module 1.0.1.0" -ForegroundColor Green

$SBquick={
  Import-Module active*
  $SRname=$parameter.SRname
  $hostname=$_
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name online -value $false
  $server | Add-Member -MemberType NoteProperty -Name ICMP -value $false
  $server | Add-Member -MemberType NoteProperty -Name SMB -value $false
  $server | Add-Member -MemberType NoteProperty -Name RDP -value $false
  $server | Add-Member -MemberType NoteProperty -Name osshort -value ""
  $server | Add-Member -MemberType NoteProperty -Name ip -value ""
  if($srname){ $server | Add-Member -MemberType NoteProperty -Name SR -value $SRname}
  $props="canonicalname","description","created","lastlogondate","operatingsystem","ipv4address"
  $ADobj=get-adcomputer $hostname -properties $props|select canonicalname, description, created,lastlogondate,operatingsystem,ipv4address
  if($ADobj){
    $server.ip=$ADobj.ipv4address
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
    $server | Add-Member -MemberType NoteProperty -Name lastlogondate -value $ADobj.lastlogondate
    $server | Add-Member -MemberType NoteProperty -Name canonicalname -value $ADobj.canonicalname
    $server | Add-Member -MemberType NoteProperty -Name description -value $ADobj.description
    $server | Add-Member -MemberType NoteProperty -Name created -value $ADobj.created
  }
  try{
    $r=New-Object System.Net.Sockets.TCPClient -ArgumentList "$($hostname)",3389
    if($r){
        $server.rdp=$true
        $server.online=$true
    
    }
  }catch{
    write-host "$hostname RDP error " -ForegroundColor red -NoNewline
  }
  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
  if(!$rtn){
    
    write-host "$hostname offline" -ForegroundColor red;
  }else{
    
    $smb=test-path "\\$($hostname)\c$" -ErrorAction SilentlyContinue
    if(!$smb) {
        Write-host -ForegroundColor red "$hostname SMB error "
    }else{
     $server.smb=$true
    }

    $server.online=$true
    $server.ICMP=$true
    $server.IP=(($rtn.properties|where {$_.name -eq "ProtocolAddress"}).value|select -first 1)
    if(!$server.IP -or $server.ip -like "*::*"){ $server.IP=($rtn|select -first 1|select IPV4Address).IPV4Address.IPAddressToString }
    if($server.ip -eq "::1"){    #get ip of local host (a crazy way ;-)
       $server.ip=Get-NetIpaddress | Where {$_.addressstate -EQ "preferred" -and $_.IPAddress.length -gt 3 -and $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "*:*"}|select -expandproperty IPAddress
    }

  }
  $server
}

$SBscanservers={
  Import-Module active*
  #$hostname = $_.name
  #$action=$parameter.action
  $action=$parameter.action
  $SRname=$parameter.SRname
  $dir=$parameter.dir
  $hostname=$_
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name OSshort -value ""
  $server | Add-Member -MemberType NoteProperty -Name online -value ""
  $server | Add-Member -MemberType NoteProperty -Name ICMP -value ""
  $server | Add-Member -MemberType NoteProperty -Name ip -value ""
  if($srname){ $server | Add-Member -MemberType NoteProperty -Name SR -value $SRname}
  
    $server | Add-Member -MemberType NoteProperty -Name domain -value ""
    $server | Add-Member -MemberType NoteProperty -Name BigFix -value ""
    $server | Add-Member -MemberType NoteProperty -Name ITM -value ""
    $server | Add-Member -MemberType NoteProperty -Name OP5 -value ""
    $server | Add-Member -MemberType NoteProperty -Name SNMPservice -value ""
    $server | Add-Member -MemberType NoteProperty -Name AV -value ""  
  $server | Add-Member -MemberType NoteProperty -Name lastlogondate -value ""
  $server | Add-Member -MemberType NoteProperty -Name canonicalname -value ""
  $server | Add-Member -MemberType NoteProperty -Name description -value ""
  $server | Add-Member -MemberType NoteProperty -Name OS -value ""
  
  $props="canonicalname","description","created","ServicePrincipalName","lastlogondate","operatingsystem","ipv4address"
  if(Get-Module -Name activedirectory){
    $ADobj=""
    try{
        $ADobj=get-adcomputer $hostname -properties $props|select ipv4address,operatingsystem,canonicalname, description, created,ServicePrincipalName,lastlogondate
    }catch{}
    if($ADobj){
        $server.lastlogondate=$ADobj.lastlogondate
        $server.canonicalname=$ADobj.canonicalname
        $server.description=$ADobj.description
        $server.IP=$ADobj.ipv4address
        $server.OS=$ADobj.operatingsystem
        if($server.OS -like "*2019*"){ $server.OSshort="w2k19"}
        if($server.OS -like "*2016*"){ $server.OSshort="w2k16"}
        if($server.OS -like "*2012*"){
	    write-host "checking R2" -foregroundcolor yellow
            if($server.OS -like "*R2*"){
                $server.OSshort="w2k12r2"
	    write-host "R2" -foregroundcolor yellow
            }else{
                $server.OSshort="w2k12"
            }
        }
        if($server.OS -like "*2008*"){ $server.OSshort="w2k8"}
        if($server.OS -like "*2003*"){ $server.OSshort="w2k3"}
        if($server.OS -like "*2000*"){ $server.OSshort="w2k"}
    }
  }
       
 
  
    $server | Add-Member -MemberType NoteProperty -Name WinRM -value ""
    $server | Add-Member -MemberType NoteProperty -Name RDP -value ""
    $server | Add-Member -MemberType NoteProperty -Name manufacturer -value ""
    $server | Add-Member -MemberType NoteProperty -Name model -value ""
    $server | Add-Member -MemberType NoteProperty -Name VMUUID -value ""
    $server | Add-Member -MemberType NoteProperty -Name AdapterMac -value ""
    $server | Add-Member -MemberType NoteProperty -Name AUOptions -value ""
    $server | Add-Member -MemberType NoteProperty -Name serverTime -value ""
  
    $server | Add-Member -MemberType NoteProperty -Name ScheduledInstallDay -value ""
    $server | Add-Member -MemberType NoteProperty -Name InstallHour -value ""
    $server | Add-Member -MemberType NoteProperty -Name lastbootuptime -value ""
    #$server | Add-Member -MemberType NoteProperty -Name rebootedBy -value ""   #this might be too slow
    $server | Add-Member -MemberType NoteProperty -Name lastpatchdate -value ""
    $server | Add-Member -MemberType NoteProperty -Name WSUSserver -value ""
    $server | Add-Member -MemberType NoteProperty -Name TargetGroup -value ""
    $server | Add-Member -MemberType NoteProperty -Name UseWUServer -value ""
    #$j=(test-path "$dir\psinfo.exe")
    #"psinfo present: $j"
    
    $server | Add-Member -MemberType NoteProperty -Name NETframework -value ""
      
  
    $server | Add-Member -MemberType NoteProperty -Name UTC_hoursOffset -value ""
    if($ADobj){$server | Add-Member -MemberType NoteProperty -Name created -value $ADobj.created}
    $server | Add-Member -MemberType NoteProperty -Name MScluster -value ""
    $server | Add-Member -MemberType NoteProperty -Name CPU -value ""
    $server | Add-Member -MemberType NoteProperty -Name CPUs -value ""
    $server | Add-Member -MemberType NoteProperty -Name coresPerCPU -value ""
    $server | Add-Member -MemberType NoteProperty -Name memory -value ""
    #$server | Add-Member -MemberType NoteProperty -Name internetAccess -value ""
    $server | Add-Member -MemberType NoteProperty -Name PSversion -value ""
    $server | Add-Member -MemberType NoteProperty -Name PowerShellMem -value ""
    $server | Add-Member -MemberType NoteProperty -Name DNSserver -value $false
    $server | Add-Member -MemberType NoteProperty -Name dynatrace -value ""
    $server | Add-Member -MemberType NoteProperty -Name TSMagent -value ""
    $server | Add-Member -MemberType NoteProperty -Name TSMagentVersion -value ""
    $server | Add-Member -MemberType NoteProperty -Name CMDBscript -value $false
    $server | Add-Member -MemberType NoteProperty -Name SNOWagent -value $false
    $server | Add-Member -MemberType NoteProperty -Name SMB -value $false
  if(get-service -cn $hostname dns){
    $server.DNSserver=$true
  }
  $tsmlog=get-childitem "\\$hostname\c$\Program Files\Tivoli\TSM\baclient\dsmsched*.log"|sort LastWriteTime|select -last 1
  if($tsmlog){
    $timespan = new-timespan -days 1
    if((get-date)-$tsmlog.lastwritetime -lt $timespan){
        $server.TSMagent=$true
    }
  }
  if(test-path "C:\Program Files (x86)\dynatrace\oneagent"){
    $server.dynatrace=$true
  }
  
  if($server|gm -name MScluster){  #check if cluster or cluster node
    $jeto=""
    #if($ADobj.ServicePrincipalName -like "*MSServerClusterMgmtAPI*"){  #this seems to be unreliable, so we rather check for Cluster Service
    if(gsv -cn $hostname clussvc -ErrorAction SilentlyContinue){
        $jeto="cluster node"
    }
    $server.mscluster=$jeto
  }
  try{
    $r=New-Object System.Net.Sockets.TCPClient -ArgumentList "$($hostname)",3389
    if($r){$server.rdp=$true}
  }catch{
    write-host "$hostname RDP error " -ForegroundColor red -NoNewline
  }
  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
  if(!$rtn){
    $server.online=$false
    $server.ICMP=$false
    write-host "$hostname does not ping" -ForegroundColor red;
    if($server.rdp){
      $server.online=$true
    }
  }else{
    $server.online=$true
    $server.ICMP=$true
  }
  
  if($server.online){   #either ping or RDP port is open

    $server.online=$true
    if($rtn){
      $server.IP=(($rtn.properties|where {$_.name -eq "ProtocolAddress"}).value|select -first 1)
      if(!$server.IP){ $server.IP=($rtn|select -first 1|select IPV4Address).IPV4Address.IPAddressToString }
      if($server.ip -eq "::1"){    #get ip of localhost (a crazy way ;-)
       $server.ip=Get-NetIpaddress | Where {$_.addressstate -EQ "preferred" -and $_.IPAddress.length -gt 3 -and $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "*:*"}|select -expandproperty IPAddress
      }
    }
        <#try{
            $parent = [System.IO.Path]::GetTempPath()
            $name = [System.IO.Path]::GetRandomFileName()
            $path=$parent+$name
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile("https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png",$path)
            if(test-path $path){
                $server.internetaccess=$true 
                remove-item $path
            }
        }catch{
            write-host " no access to internet " -ForegroundColor yellow -NoNewline
        }#>

        $winrm="OK"
        if($server|gm -name winrm){
            try{
                $res=Test-WSMan -cn $hostname -ErrorAction Stop
            }catch{
                write-host "$hostname WinRM error" -ForegroundColor yellow;
                $winrm="error"
            }
            $server.winrm=$winrm
            $server.PSversion=invoke-command -cn $hostname {[string]($PSVersionTable.psversion.Major)+"."+[string]($PSVersionTable.psversion.minor)}
            $server.PowerShellMem=invoke-command -cn $hostname {Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB|select -expandproperty value}
        }
     
        $wmiok=$true
        $wmi=get-wmiobject -computer $hostname win32_operatingsystem -ErrorAction SilentlyContinue
        if(!$wmi){
            write-host "$hostname WMI error" -ForegroundColor DarkYellow;
            $wmiok=$false
        }
        if($wmiok){
            $server.OS=$wmi.caption
            if($wmi.name -like "*2019*"){ $server.OSshort="w2k19"}
            if($wmi.name -like "*2016*"){ $server.OSshort="w2k16"}
            if($wmi.name -like "*2012*"){
		if($wmi.name -like "*R2*"){
			$server.OSshort="w2k12r2"
		}else{
			$server.OSshort="w2k12"
		}
	    }
            if($wmi.name -like "*2008*"){ $server.OSshort="w2k8"}
            if($wmi.name -like "*2003*"){ $server.OSshort="w2k3"}
            $lb=$wmi.ConvertToDateTime($wmi.lastbootuptime)
            $server.lastbootuptime=$lb
            $wmi=get-wmiobject -computer $hostname Win32_TimeZone -ErrorAction SilentlyContinue
            $tz=$wmi.caption -split("\)")
            $server.UTC_hoursOffset=$tz[0].substring(1)
            if($action -ne "short"){
                $wmi=Get-wmiobject -cn $hostname win32_computersystem -ErrorAction SilentlyContinue|select domain,model,manufacturer,NumberOfProcessors #select @{Label='model1';Expression={$_.model}}
                $server.model=$wmi.model
                $server.domain=$wmi.domain
                $server.manufacturer=$wmi.manufacturer
                if($server|gm -name CPUs){$server.CPUs=$wmi.NumberOfProcessors}
            }
            $wmi=Get-WmiObject -cn $hostname Win32_Processor | Select -First 1|select name,numberofcores
            $server.CPU=$wmi.name
            $server.coresPerCPU=$wmi.numberofcores
            $server.memory=Get-WMIObject -cn $hostname Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)}
            $wmi=Get-WmiObject -cn $hostname Win32_bios | Select -First 1|select serialnumber
            $server.VMUUID=$wmi.serialnumber
            $str=getmac|findstr Device
            $server.adaptermac=($str -split " ")[0]

            $server.TSMagentversion=Get-WmiObject -cn $hostname Win32_Product -Filter "Name like 'IBM spectrum protect client'"|Select-Object -ExpandProperty Version
        }

        $smb=test-path "\\$($hostname)\c$" -ErrorAction SilentlyContinue
        if(!$smb) {
            Write-host -ForegroundColor red "$hostname SMB error"
        }else{
            $server.smb=$true
            if(test-path("\\$hostname\c$\windows")){
                if(!(test-path("\\$hostname\c$\windows\explorer.exe"))){
                    $server.OSshort+=" core"
                    $server.OS+=" core"
                }
            }
    
            if (gsv -cn $hostname besclient -ErrorAction SilentlyContinue){
                $server.bigfix=$true
            } else {
                $server.bigfix=$false
            }
            if (gsv -cn $hostname KNTCMA_Primary -ErrorAction SilentlyContinue){
                $server.ITM=$true
            } else {
                $server.ITM=$false
            }
            if (gsv -cn $hostname NSClientpp -ErrorAction SilentlyContinue){
                $server.OP5=$true
            } else {
                if (gsv -cn $hostname nscp -ErrorAction SilentlyContinue){
                    $server.OP5=$true
                }else{
                    $server.OP5="no"
                }
            }
            if (gsv -cn $hostname SNMP -ErrorAction SilentlyContinue){
                $server.SNMPservice=$true
            } else {
                $server.SNMPservice=$false
            }
            if ((test-path "\\$($hostname)\c$\Program Files\Trend Micro") -or (test-path "\\$($hostname)\c$\Program Files (x86)\Trend Micro")) {
                $server.av="Trend Micro"
            }else{
                if (test-path "\\$($hostname)\c$\Program Files (x86)\Kaspersky Lab") {
                    $server.av="Kaspersky Lab"
                }else{
                    if (test-path "\\$($hostname)\c$\Program Files (x86)\Symantec") {
                        $server.av="Symantec"
                    }else{
                        if (test-path "\\$($hostname)\c$\Program Files (x86)\McAfee") {
                            $server.av="McAfee"
                        }else{
                            if (test-path "\\$($hostname)\c$\Program Files (x86)\Panda Security") {
                                $server.av="Panda Security"
                            }
                        }
                    }
                }
            }
        }
        
        #$server.WindowsUpdateSvc=(gsv -cn $hostname wuauserv).status
        try{$RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$hostname)}catch{}
        if($RegCon){
            <#$RegWUAU = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\") 
	        $RegWUAURebootReq = $RegWUAU.GetSubKeyNames() 
	        $WUAURebootReq = $RegWUAURebootReq -contains "RebootRequired"
            $server.WU_requiresReboot=$WUAURebootReq
            $Regkey = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect")
            if($regkey){
                $server.lastWUdetectResult='{0:x}' -f $RegKey.GetValue("LastError")
                if($server.os -like "*2016*"){
                    $server.LastSuccessTime=(Get-WinEvent -cn $hostname -LogName Microsoft-Windows-WindowsUpdateClient/Operational | where{$_.Id -match "26"} | select TimeCreated -First 1).timecreated
                }else{
                    $server.LastSuccessTime=$RegKey.GetValue("LastSuccessTime")
                }
            }
            $Regkey = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download")
            if($Regkey){
                $server.lastWUdownloadResult='{0:x}' -f $RegKey.GetValue("LastError")
            }
            $Regkey = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install")
            if($regkey){ $server.lastWUinstallResult='{0:x}' -f $RegKey.GetValue("LastError")}
            #>
            $Regkey = $RegCon.OpenSubKey("Software\Policies\Microsoft\Windows\WindowsUpdate")
            if($regkey){
                if($server|gm -name WSUSserver){$server.WSUSserver=$RegKey.GetValue("WUServer")}
                if($server|gm -name TargetGroup){$server.TargetGroup=$RegKey.GetValue("TargetGroup")}
            }
            
            $Regkey = $RegCon.OpenSubKey("Software\Policies\Microsoft\Windows\WindowsUpdate\AU")
            if($regkey){
                $auo=$RegKey.GetValue("AUOptions")
                if($server|gm -name AUOptions){
                    switch($auo){
                        2{$server.AUOptions=2; break}
                        3{$server.AUOptions=3; break}
                        4{
                            $server.AUOptions=4;
                        $day=$RegKey.GetValue("ScheduledInstallDay")
                            switch($day){
                                0 { $server.ScheduledInstallDay="ANY"; break }
                                1 { $server.ScheduledInstallDay="Sunday"; break }
                                2 { $server.ScheduledInstallDay="Monday"; break }
                                3 { $server.ScheduledInstallDay="Tuesday"; break }
                                4 { $server.ScheduledInstallDay="Wednesday"; break }
                                5 { $server.ScheduledInstallDay="Thursday"; break }
                                6 { $server.ScheduledInstallDay="Friday"; break }
                                7 { $server.ScheduledInstallDay="Saturday"; break }
                            }
                            $server.InstallHour=$RegKey.GetValue("ScheduledInstallTime")
                            break
                        }
                        5{$server.AUOptions="Automatic Updates is required and users can configure it"; break}
                    }            
                }
                if($server|gm -name UseWUServer){$server.UseWUServer=($RegKey.GetValue("UseWUServer") -eq $true)}
            }
            <#$Regkey = $RegCon.OpenSubKey("system\CurrentControlSet\Services\wuauserv")
            if($regkey){
            $val=$RegKey.GetValue("Start")
            switch($val){
                2 { $server.WindowsUpdateSvcStartup="WUsvc_automatic";break }
                3 { $server.WindowsUpdateSvcStartup="WUsvc_manual";break }
                4 { $server.WindowsUpdateSvcStartup="WUsvc_disabled";break }
                }
            }
            #>
            $RegCon.Close()
        }
        if($server|gm -name NETframework){
            try{$RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$hostname)}catch{}
            $ver=""
            if($RegCon){
                $RegNETf = $RegCon.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\")
                $subkeys=$RegNETf.GetSubKeyNames()
                if($subkeys -contains "v2"){$ver="2.x"}
                if($subkeys -contains "v3"){$ver="3.x"}
                if($subkeys -contains "v3.5"){$ver="3.5.x"}
                if($subkeys -contains "v4"){$ver="4.x"}
            }
            $server.NETframework=$ver
            $RegCon.Close()
        }
        if($server|gm -name serverTime){
            $r=invoke-command -cn $hostname {[DateTime]::Now.ToString("HH:mm:ss")}
            $server.serverTime=$r
        }
        if($server|gm -name lastpatchdate){
            clear-variable $lastpatchdate
            $lastpatchdate=(get-hotfix -cn $hostname| Select InstalledOn| sort InstalledOn | select -last 1).InstalledOn
            $server.lastpatchdate=$lastpatchdate
        }
  }
  $server
}

$SBgetevents={
  $hostname=$_
  $dir=$parameter.dir
  $logname=$parameter.logname
  $eventids=$parameter.eventids
  $par=$parameter.par
  $days=$parameter.days
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name events -value $null
  

  #$days=20
  $datefrom=(Get-Date).AddDays(-$days)
  #$logname="setup"
  if($par -eq 2){
    $events=Get-WinEvent -cn $hostname -FilterHashTable @{LogName=$logname; id=$eventids; StartTime=$datefrom}|select TimeCreated,Id,LevelDisplayName,ProviderName,Message
    if(!(test-path "$dir\reports\events")){ new-item "$dir\reports\events" -ItemType directory}
    $count=$events|measure-object|select -expandproperty count
    if($count -gt 0){
        $events|export-csv "$dir\reports\events\$hostname.csv" -NoTypeInformation
        $server.events="reports\events\$hostname.csv"
    }else{
        $server.events="no events found"
    }
  }else{
    $server.events=Get-WinEvent -cn $hostname -FilterHashTable @{LogName=$logname; id=$eventids; StartTime=$datefrom}|select TimeCreated,Id,LevelDisplayName,ProviderName,Message
  }
  $server
}

$inventorymodule=$true
