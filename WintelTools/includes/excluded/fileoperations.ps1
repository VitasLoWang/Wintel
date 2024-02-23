$SBcopyfiles={   #scriptblock

        $mode=$parameter.mode
        $source=$parameter.files
        $destination=$parameter.destination
        $SAcredlist=$parameter.SAcredlist
        #$kbs=$parameter.kbs
        #$dayshistory=$parameter.dayshistory
        $ip=$_

if($mode -eq "winrm"){
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
    $result=Copy-Item –Path $source –Destination $destination –ToSession $sess
    $sess|remove-pssession
    $result
}else{
    $result=Copy-Item –Path $source –Destination $destination
    $result
}
}