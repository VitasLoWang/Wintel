#this is an include file for WintelTools.ps1

write-host "custom module 1.0.0.1" -ForegroundColor Green

$SB_NETframework={ #scriptblock
Import-Module active*
  $action=$parameter.action
  $SRname=$parameter.SRname
  $dir=$parameter.dir
  $hostname=$_
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name OSshort -value ""
  $server | Add-Member -MemberType NoteProperty -Name online -value ""
  $server | Add-Member -MemberType NoteProperty -Name ip -value ""
  $server | Add-Member -MemberType NoteProperty -Name OS -value ""
  
  $props="canonicalname","description","created","ServicePrincipalName","lastlogondate","operatingsystem","ipv4address"
  if(Get-Module -Name activedirectory){
    $ADobj=""
    try{
        $ADobj=get-adcomputer $hostname -properties $props|select ipv4address,operatingsystem,canonicalname, description, created,ServicePrincipalName,lastlogondate
    }catch{}
    if($ADobj){
        $server.IP=$ADobj.ipv4address
        $server.OS=$ADobj.operatingsystem
        if($server.OS -like "*2019*"){ $server.OSshort="w2k19"}
        if($server.OS -like "*2016*"){ $server.OSshort="w2k16"}
        if($server.OS -like "*2012*"){
            if($server.OS -like "*R2*"){
                $server.OSshort="w2k12r2"
            }else{
                $server.OSshort="w2k12"
            }
        }
        if($server.OS -like "*2008*"){ $server.OSshort="w2k8"}
        if($server.OS -like "*2003*"){ $server.OSshort="w2k3"}
        if($server.OS -like "*2000*"){ $server.OSshort="w2k"}
    }
  }
       
 
  $server | Add-Member -MemberType NoteProperty -Name NETframework -value ""

  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue
  if(!$rtn){
    $server.online=$false
    write-host "$hostname does not ping" -ForegroundColor red;
    if($server.rdp){
      $server.online=$true
    }
  }else{
    $server.online=$true
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
        if($server|gm -name NETframework){
            try{$RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$hostname)}catch{}
            $ver=""
            if($RegCon){
                $RegNETf = $RegCon.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\")
                $subkeys=$RegNETf.GetSubKeyNames()
                if($subkeys -contains "v2"){$ver="2.x"}
                if($subkeys -contains "v3"){$ver="3.x"}
                if($subkeys -contains "v3.5"){$ver="3.5.x"}
                if($subkeys -contains "v4"){
                    $RegNETf2 = $RegCon.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\")
                    #$RegNETf2.GetSubKeyNames()
                    $release=$RegNETf2.GetValue("Release")
                    write-host "$hostname .NET release: $release"
                    if($release -contains "378389"){$ver="4.5"}
                    if($release -contains "378675"){$ver="4.5.1"}
                    if($release -contains "379893"){$ver="4.5.2"}
                    if($release -contains "393297"){$ver="4.6"}
                    if($release -contains "394254" -or $release -contains "394271"){$ver="4.6.1"}
                    if($release -contains "394802" -or $release -contains "394806"){$ver="4.6.1"}
                    if($release -contains "460798" -or $release -contains "460805"){$ver="4.7"}
                    if($release -contains "461308" -or $release -contains "461310"){$ver="4.7.1"}
                    if($release -contains "461808" -or $release -contains "461814"){$ver="4.7.2"}
                    if($release -contains "528040" -or $release -contains "528372" -or $release -contains "528449" -or $release -contains "528049"){$ver="4.8"}
                }
            }
            $server.NETframework=$ver
            $RegCon.Close()
        }
        
  }
  $server
}

$SBrunexe_SAservers={   #scriptblock

        $srname=$parameter.SRname
        $command=$parameter.command
        $SAcredlist=$parameter.SAcredlist
        #$ip=$_
        #$hn=$parameter.csvlist|where ip -eq $ip|select -expandproperty hostname
        #write-host "$hn $ip"
        $hostname=$_
$sess=get-pssession -name $hostname -erroraction silentlycontinue
if(!$sess){
    if($sacredlist|where name -eq "$hostname.xml"){   #checks for stand-alone credentials file
        write-host "$hostname loading credentials "$env:appdata"\creds\sa\"$hostname".xml"
        $sacreds=Import-CliXml -Path $env:appdata"\creds\sa\"$hostname".xml"
        write-host "loaded :"$sacreds
        $sess=new-PSSession -ComputerName $hostname -Credential $sacreds -errorvariable connerr
    }else{
        $sess=new-PSSession -ComputerName $hostname -Credential $parameter.Credentials -errorvariable connerr
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
    if($parameter.workdir){
        $cmdstring="cd $workdir\r\n"
    }
    $cmdstring=$cmdstring+$command
    write-host "CMDSTRING: "
    write-host $cmdstring
    #$res=
    #$scriptBlock = [Scriptblock]::Create($cmdstring)
    #invoke-command -session $sess -ScriptBlock { $scriptBlock }
    invoke-command -session $sess -ScriptBlock { md c:\kyndryl }
    invoke-command -session $sess -ScriptBlock { C:\ibm\iam_extract.exe }

}
}

$SBagentremovalStatus={
  $action=$parameter.action
  $SRname=$parameter.SRname
  $dir=$parameter.dir
  $hostname=$_
  $server = New-Object -TypeName psobject
  $server | Add-Member -MemberType NoteProperty -Name hostname -Value $hostname
  $server | Add-Member -MemberType NoteProperty -Name online -value ""
  $server | Add-Member -MemberType NoteProperty -Name BigFix -value ""
  $server | Add-Member -MemberType NoteProperty -Name ITM -value ""
  $server | Add-Member -MemberType NoteProperty -Name AV -value ""
  $server | Add-Member -MemberType NoteProperty -Name CMDBscript -value $false
  $server | Add-Member -MemberType NoteProperty -Name SNOWagent -value $false
  $server | Add-Member -MemberType NoteProperty -Name dynatrace -value ""
  
  $rtn=test-connection $hostname -Count 2 -BufferSize 16 -erroraction silentlycontinue  
  if(!$rtn){
    $server.online=$false
    write-host "$hostname offline" -ForegroundColor red;
  }else{
    $server.online=$true

    $logf=get-childitem \\$hostname\c$\temp\ -Filter "CMDBandSNOW*"
    if(!$logf){
        $server.CMDBscript=$false
        $server.SNOWagent=$false
    }else{
        $server.CMDBscript=$true
        $server.SNOWagent=$true
    }

    if($logf){
        $res=gc \\$hostname\c$\temp\$Logf
        if(!($res -like "*install.cmd ended with code 0*")){
            $server.CMDBscript="error"
            $server.SNOWagent="error"
        }
    }
    if(test-path "C:\Program Files (x86)\dynatrace\oneagent"){
        $server.dynatrace=$true
    }
    if (gsv -cn $hostname KNTCMA_Primary -ErrorAction SilentlyContinue){
        $server.ITM=$true
     } else {
        $server.ITM=$false
     }
     if(gsv -cn $hostname besclient -ErrorAction SilentlyContinue){
        $server.BigFix="servicerunning"
     }else{
        if(test-path "\\$hostname\c$\Program Files (x86)\BigFix Enterprise"){
            $server.BigFix="folderstillthere"
        }else{
            $server.BigFix="uninstalled"
        }
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
  $server
}