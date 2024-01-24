#UNC supported too
param (
[Parameter(Mandatory)]$source,
[Parameter(Mandatory)]$target    #use full path
)
$stopOnCopyError=$true
$alsodelete=$true      #if set to false it will not remove items from target folder

function global:log
(
    [string] $message
) {
    Process {
         [DateTime]::Now.ToString("yyyy/MM/dd-HH:mm:ss")+" "+$message|out-file ("$dir\FolderSync-"+$($env:computername+".log")) -append
    }
}

function testlocation
(
    [string] $path,
    [string] $type
) {
Process {
if(test-path $path){
    if((get-item($path) -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo]){
        $PathInfo=[System.Uri]$path
        $ismapped=$false
        if($PathInfo.IsUnc){
            $ismapped=$true
        }else{
            $driveLetter=Split-Path -Path $path -qualifier
            #write-host "driveletter" $driveLetter
            $mappeddrives=Get-SMBMapping
            $mappeddrives|foreach {
                if($_.LocalPath -eq $driveletter){ $ismapped=$true}
            }
        }
        if($ismapped){    
            log($type+" is a network location")
            write-host $type" is a network location"
        }
    }else{
        log($type+" must be a folder!")
        write-host $type" must be a folder!" -foregroundcolor red
        return $false
    }
    return $true
}else{
    if($type -eq "target"){
        $parentDirectory=Split-Path -Path $path -Parent
        if(test-path $parentDirectory){
            log("creating target folder $path")
            $res=new-item $path -ItemType directory
            if(!$res){
                log("ERROR writing to target folder! Check permissions")
                write-host "ERROR writing to target folder! Check permissions" -foregroundcolor red
                return $false
            }
        }else{
            log($type+" parent folder "+$parentDirectory+" inaccessible or not existing!")
            write-host $type $parentDirectory" folder inaccessible or not existing!" -foregroundcolor red
            return $false
        
        }
    }else{  #$type="source" and $path not found
        log($type+" "+$path+" inaccessible or not existing!")
        write-host $type $path" folder inaccessible!" -foregroundcolor red
        return $false
    }            
    return $true
}
} #I don't like too much of unnecessary indentation ;)
}

if ($source[-1] -eq "\") {   #remove trailing backslashes
    $source=$source.Substring(0,($source.Length-1))
}
if ($target[-1] -eq "\") {
    $target = $target.Substring(0,($target.Length-1))
}

$scriptpath=$MyInvocation.MyCommand.Path
$dir = Split-Path $scriptpath
cd $dir
log " "
log "FolderSync 1.0 starting"
write-host "FolderSync 1.0 starting and logging into $dir\" -ForegroundColor cyan
write-host "source: $source"
write-host "target: $target"
if($source -eq "" -or $target -eq ""){
    log "you need to set source and target folders in the code"
    write-host "you need to set source and target folders in the code" -ForegroundColor red
    return 2
}
if($source -eq $target){
    log "target and source are the same!"
    write-host "target and source are the same!" -ForegroundColor Red
    return 2
}

$sourcevalid=testlocation -path $source -type "source"
$targetvalid=testlocation -path $target -type "target"
if(!($sourcevalid -and $targetvalid)){
    return 2
}
cd $source
$sourceitems=get-childitem $source -recurse
$sourceitemscount=$sourceitems|measure-object
log([string]$sourceitemscount.count+" items found in source folder")
write-host $sourceitemscount.count"items found in source folder"
$sourcename=Split-Path -Path $source -leaf
$targetname=Split-Path -Path $target -leaf
if($sourcename -ne $targetname){
    log("WARNING: target folder name is different from source. Is this intentional?")
    write-host "WARNING: target folder name is different from source. Is this intentional?" -ForegroundColor yellow
    $targetitems=get-childitem $target -recurse
    $targetitemscount=$targetitems|measure-object|select -expandproperty count
    if($targetitemscount -gt 0){
        log("target folder already has items. They will be removed if not present in source!")
        write-host "target folder already has items. They will be removed if not present in source!" -ForegroundColor yellow
        $choice=read-host "is this OK? (y to continue, anything else to quit)"
        if($choice -ne "y"){
            cd $dir
            return 2
        }
    }
}

$sourceitems|ForEach-Object {
    #check if this item exists in target folder
    #$_.name
    $relpath=$_|Resolve-Path -Relative
    if(($relpath).substring(0,2) -ne ".\"){   #looks like some weird bug of Resolve-Path when name starts with .
        $relpath="\"+$relpath
    }else{
        $relpath=$relpath.Substring(1)
    }
    $targetpath=$target+$relpath
    #write-host "relpath $relpath"
    if(!(test-path ($targetpath))){
        write-host "copying"($_.fullname)"to $targetpath"
        log("copying "+($_.fullname)+" to "+$targetpath)
        try{
            Copy-Item $_.FullName $targetpath
        }catch{
            log("ERROR during copy operation!")
            write-host "ERROR during copy operation!"
            if($stopOnCopyError){
                return 3
            }
        }
    }else{   #check modifytimestamps
        $sourcets=$_.LastWriteTime
        $targetts=(get-item $targetpath).LastWriteTime
        #write-host $sourcets" ~ "$targetts
        if($sourcets -ne $targetts -and $_ -isnot [System.IO.DirectoryInfo]){  #if timestamps differ and it's not a folder
            log("updating $targetpath")
            write-host "updating $targetpath"
            try{
                Copy-Item $_.FullName $targetpath -force
            }catch{
                log("ERROR during copy operation!")
                write-host "ERROR during copy operation!"
                if($stopOnCopyError){
                    return 3
                }
            }
        }
    }
}
#check for deleted items in source
if(!$alsodelete){
    return 0
}
write-host "check for deleted items in source"
cd $target
$targetitems=get-childitem $target -recurse
$targetitems|ForEach-Object {
    #check if this item exists in source folder
    #$_.FullName
    $relpath=$_|Resolve-Path -Relative -ErrorAction SilentlyContinue
    if($relpath){   #if it's in a folder which was already deleted before in this cycle then skip the check
        if(($relpath).substring(0,2) -ne ".\"){   #looks like some weird bug of Resolve-Path when name starts with .
            $relpath="\"+$relpath
        }else{
            $relpath=$relpath.Substring(1)
        }
        $sourcepath=$source+$relpath
        #write-host $sourcepath
        if(!(test-path $sourcepath)){
            write-host "$sourcepath no longer in source. Deleting in target"
            log("$sourcepath no longer in source. Deleting in target")
            Remove-Item $_.fullname -force -recurse
        }
    }
}
cd $dir
