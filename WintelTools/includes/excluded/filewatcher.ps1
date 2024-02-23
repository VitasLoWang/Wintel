
$global:appstatus=[pscustomobject] @{
    filepresent=$false
    filemodify=""
    filesize=0
    avgchangefreq=1
    readfrequency=1
    changed=$false
    linesToread=30
    state="watching"
    mode="c"
    string=""
    content=@()
}

$fileversion="1.0.1.0"

function rewrite(){
clear-host
write-host "=========================================================================================="
write-host "File Watcher $fileversion " -ForegroundColor magenta -nonewline
write-host ($appstatus.state)"$filename " -ForegroundColor cyan -NoNewline
if($appstatus.filepresent){
    write-host "file present:"($appstatus.filepresent)
}else{
    write-host "file present:"($appstatus.filepresent) -ForegroundColor red
}
if($appstatus.filepresent){
    write-host "last modify:"($appstatus.filemodify) -NoNewline
    write-host " | size:"($appstatus.filesize) -NoNewline
    write-host " | read frequency:"($appstatus.readfrequency)"s" -NoNewline
    if($appstatus.mode -eq "s"){
        write-host
        write-host "looking for string: "$appstatus.string
    }else{
        write-host " | lines to read:"($appstatus.linesToread)
    }
}
write-host "================ " -nonewline
write-host "press P to pause, S to change settings, Q to quit" -nonewline -ForegroundColor cyan
write-host " ======================="
if($appstatus.content){
 $appstatus.content
}
}

function readfile(){
        $starttime=(get-date)
        $appstatus.content=gc $filename|select-object -last $appstatus.linesToread
        $stoptime=(get-date)
        $sec=($stoptime-$starttime).seconds
        if($sec -gt $appstatus.readfrequency){ $appstatus.readfrequency=$sec}  #decreasing read frequency to lower disk/network load
        $appstatus.changed=$false
}
function searchstring(){
"searchstring"
        $starttime=(get-date)
        $appstatus.content=select-string -pattern $appstatus.string -path $filename -context $appstatus.linesToread
        $stoptime=(get-date)
        $sec=($stoptime-$starttime).seconds
        if($sec -gt $appstatus.readfrequency){ $appstatus.readfrequency=$sec}  #decreasing read frequency to lower disk/network load
        $appstatus.changed=$false
}    
function settings($mode="c"){
            write-host "settings"
            if($mode -eq "c"){
                $inputOK=$false
                while(!$inputOK){
                    write-host "choose run mode" -ForegroundColor cyan
                    write-host "c - watch file content"
                    write-host "s - look for specific string"
                    $q=read-host "mode"
                    if(("c","s") -contains $q){$inputok=$true}
                }
            }else{
                $q="s"
            }
            if($q -eq "c"){
                $appstatus.mode="c"
                $inputOK=$false
                while(!$inputOK){
                    $p=read-host "number of lines to read"
                    try{$p=[int]$p; $inputOK=$true}catch{$inputOK=$false}
                }
                $appstatus.linesToRead=$p
                readfile
            }else{
                $appstatus.string=""
                while($appstatus.string -eq ""){
                    $appstatus.string=read-host "enter string to watch for"
                }
                $appstatus.mode="s"
                
            }
            if($appstatus.mode -eq "c"){
                $refresh=$true
                return
            }
            $inputOK=$false
            while(!$inputOK){
                $p=read-host "number of lines to show before and after (context)"
                try{$p=[int]$p; $inputOK=$true}catch{$inputOK=$false}
            }
            $appstatus.linesToRead=$p
            searchstring
            $refresh=$true
            $appstatus.changed=$true
}
function isfolder($fn){
if((get-item($fn) -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo]){
    write-host "$fn is a folder." -foregroundcolor red
    write-host "If you want to watch multiple files, use wildcards like somepath\*.log for example"
    read-host "press enter to quit"
    $global:run=0
    return
}
}

if($Args[0]){
    $filename=[System.String]$Args[0]
    $filename
}else{
    write-host "you need to run this with path to file parameter"
    read-host "press enter to continue"
    return
}
if($Args[1]){
    if(("s","c") -contains $Args[1]){
        $appstatus.mode=$Args[1]
        settings($Args[1])
    }else{
        write-host "second parameter can be either c or s (content or string search mode)"
        read-host "press enter to continue"
        return        
    }
}
$global:run=1
isfolder $filename
if(!$run){ return }
$c=0
$refresh=$false
rewrite
while($run){
    if(test-path($filename)){
        isfolder $filename
        if(!($appstatus.filepresent)){$refresh=$true}
        $appstatus.filepresent=$true               #file found
    }else{
        if($appstatus.filepresent){$refresh=$true}
        $appstatus.filepresent=$false
    }
    if($c % 2 -eq 0 -and !($appstatus.filepresent) -and $appstatus.state -eq "watching"){   #file not found
        if(test-path($filename)){
            $appstatus.filepresent=$true               #file found
            $refresh=$true
        }
    }
    if($c % 1 -eq 0 -and $appstatus.filepresent -and $appstatus.state -eq "watching"){
        $o=get-item $filename
        if(!$o){
            $appstatus.filepresent=$false
            $refresh=$true
            continue
        }
        if($o.LastWriteTime -ne $appstatus.filemodify){ #file changed
            $appstatus.filemodify=$o.LastWriteTime
            $appstatus.filesize=$o.length
            $appstatus.changed=$true
        }
    }
    if(($c % $appstatus.readfrequency) -eq 0 -and $appstatus.filepresent -and $appstatus.changed){
        if($appstatus.mode -eq "c"){
            readfile
        }else{
            searchstring
        }
        $refresh=$true
    }
        
    if ([Console]::KeyAvailable){
        $keyInfo = [Console]::ReadKey($true)
        if($keyInfo.key -eq "p"){
            if($appstatus.state -eq "watching"){
                $appstatus.state="PAUSED"
                $refresh=$true
            }else{
                $appstatus.state="watching"
                $refresh=$true
            }
        }
        if($keyInfo.key -eq "s"){
            settings
            "settings saved"
            $refresh=$true
            $appstatus.changed=$true
        }
        if($keyInfo.key -eq "q"){
            "tip: you can also use wildcards in path to watch multiple files!"
            $run=0
        }
    }
    if($refresh){
        rewrite
        $refresh=$false
    }
    start-sleep -Milliseconds 1000
    $c++
    if($c -gt 1023){$c=0}
}