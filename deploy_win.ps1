Param (
[Parameter(Position=0, Mandatory=$True)]$ZbxHostName,
[Parameter(Position=1)]$DelMissing = 0,
[Parameter(Position=2)]$DebugMe = 0
)

$ErrorVar = 0
$Result = ''
$ErrorMsg = @()
$UpdateError = @()
$Data = @()

#region functions

function Get_Zabbix_Address{
    $ServicePaths = (Get-WmiObject win32_service | Where-Object {$_.State -match "running"} | Where-Object {$_.Name -like "Zabbix Agent"} | Select-Object PathName).PathName.Split('-') | Select-Object -First 1 -Last 1 | ForEach-Object {$_.split('"')[1]}
    Get-Content $ServicePaths[1] | foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True) -and (($k[0].StartsWith("Server") -eq $True) -or ($k[0].StartsWith("server") -eq $True))) {$h.Add($k[0], $k[1])}}
    $ZabbixSender = (Get-Item $ServicePaths[0]).Directory.FullName + '\zabbix_sender.exe'
    $ZbxSrv = $h.ServerActive.Split(':')[0]
    $ScriptPath = 'C:\Program Files\Zabbix Agent\scripts'
    if($h.ServerActive.Split(':')[1]){$ZbxPort = $h.ServerActive.Split(':')[1]} else{$ZbxPort = 10051}
    $ZabbixServer = New-Object PsObject -Property @{addr=$ZbxSrv ; port=$ZbxPort ; sender=$ZabbixSender; script=$ScriptPath}
        return $ZabbixServer
}

function Get_FileHash($path){
        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($Path)))
        $hash = $hash.Replace('-', '')
        return $hash
}

function Web_Request ($url){
        $WebRequest = [System.Net.WebRequest]::Create($url)
        $WebRequest.Method = "GET"
        $WebRequest.Timeout = 15000
        try {$Response = $WebRequest.GetResponse()}
        catch {return 0}
        $ResponseStream = $Response.GetResponseStream()
        $ReadStream = New-Object System.IO.StreamReader $ResponseStream
        $Data=$ReadStream.ReadToEnd()
        return $Data
}

function Translit {
    param([string]$inString)
    try {
        $translitHash = @{
        [char]'а' = "a"; [char]'А' = "a"; [char]'б' = "b"; [char]'Б' = "b"; [char]'в' = "v"; [char]'В' = "v"; [char]'г' = "g"; [char]'Г' = "g";
        [char]'д' = "d"; [char]'Д' = "d"; [char]'е' = "e"; [char]'Е' = "e"; [char]'ё' = "e"; [char]'Ё' = "e"; [char]'ж' = "zh"; [char]'Ж' = "zh";
        [char]'з' = "z"; [char]'З' = "z"; [char]'и' = "i"; [char]'И' = "i"; [char]'й' = "i"; [char]'Й' = "i"; [char]'к' = "k"; [char]'К' = "k";
        [char]'л' = "l"; [char]'Л' = "l"; [char]'м' = "m"; [char]'М' = "m"; [char]'н' = "n"; [char]'Н' = "n"; [char]'о' = "o"; [char]'О' = "o";
        [char]'п' = "p"; [char]'П' = "p"; [char]'р' = "r"; [char]'Р' = "r"; [char]'с' = "s"; [char]'С' = "s"; [char]'т' = "t"; [char]'Т' = "t";
        [char]'у' = "u"; [char]'У' = "u"; [char]'ф' = "f"; [char]'Ф' = "f"; [char]'х' = "kh"; [char]'Х' = "kh"; [char]'ц' = "tc"; [char]'Ц' = "tc";
        [char]'ч' = "ch"; [char]'Ч' = "ch"; [char]'ш' = "sh"; [char]'Ш' = "sh"; [char]'щ' = "shch"; [char]'Щ' = "shch"; [char]'ъ' = ""; [char]'Ъ' = "";
        [char]'ы' = "y"; [char]'Ы' = "y"; [char]'ь' = ""; [char]'Ь' = ""; [char]'э' = "e"; [char]'Э' = "e"; [char]'ю' = "iu"; [char]'Ю' = "iu";
        [char]'я' = "ia"; [char]'Я' = "ia"; [char]' ' = "_"
        }
    }
    catch{
        $translitHash = @{}
    }
    $outChars=""
    foreach ($c in $inChars = $inString.ToCharArray()) {
        if ($translitHash[$c] -cne $Null ) {
            $outChars += $translitHash[$c]
        }
        else {
            $outChars += $c
        }
    }
    return $outChars
}

function Data_send($sdata, $ZabbixServer) {
    $ZabbixSender = $ZabbixServer.sender
    $argSrv = '-z' + $ZabbixServer.addr
    $argPort = '-p' + $ZabbixServer.port
    foreach ($ZHost in $sdata){
            $currentHost = $zhost.keys
                $currentHost = [string]$currentHost
                foreach ($Valueq in $ZHost.$currentHost){
                        $currnetValue = $Valueq.keys
                        $currnetValueName = [string]$currnetValue
            $ZValue = $Valueq.$currnetValueName
            $ZValue = Translit $Zvalue #Added 01.04 transliting function
            $argHostName = '-s' + $ZbxHostName
            $argKey = '-k' + $currnetValueName
            $argValue = "-o" + "$ZValue"
            & $ZabbixSender $argSrv $argPort $argHostName $argKey $argValue > $null 2>&1
            if ($DebugMe -eq 1) {Write-host $ZabbixSender $argSrv $argPort $argHostName $argKey $argValue}
        }
    }
}

function Get_TimeStamp{
    return (Get-Date -Format o).Substring(0,19).Replace(':', '-')
}


function Get_Remote_Files{
    $RemoteFiles = @()
    $ListUrl = $Url_Base + '/windows_list.md5'
        $Response = Web_Request($ListUrl)
    if ($Response){
        $Response = $Response -split "`n"
        $Regex_Pattern = '^[0-9a-z]{32}\s\s\\.*'
        foreach ($ResponseLine in $Response){
            if($ResponseLine -match $Regex_Pattern){
                $RemoteFiles += ($ResponseLine)
            }
        }
    }
    else{
        $RemoteFiles = 0
    }
        if ($DebugMe -eq1) {write-host "Remote files are $RemoteFiles"}
        return $RemoteFiles
}


function Get_Local_Files{
    $LocalFiles = @()
        $LocalFilesSearch = Get-ChildItem -Path $ZabbixServer.script -Recurse | Where-Object { !$_.PSIsContainer } | Select-Object FullName | Where-Object { $_.FullName -inotmatch 'deploy_backup' }
        if ($LocalFilesSearch) {
                foreach ($file in $LocalFilesSearch){
                        $Hash = Get_FileHash $file.FullName
                        $FilePath = $file.FullName.Replace($ZabbixServer.script, '')
                        $LocalFiles += ($Hash.ToLower() + '  ' + $FilePath)
                }
    }
        if ($DebugMe -eq 1) {write-host "Local files are $LocalFiles"}
        return $LocalFiles
}


function Compare_Repos($Remote, $Local){
    [hashtable]$return = @{}
    $GetUrl = $Url_Base + '/local_scripts_windows'
    if($Remote){
        $Remote_FileName = $Remote | % {$_.Split(' ', 3)[2]}
        if($Local){
            $Local_FileName = $Local | % {$_.Split(' ', 3)[2]}
            $InterSect = Compare-Object $Remote $Local -PassThru -IncludeEqual -ExcludeDifferent
            if($InterSect){
                $Intersect_FileName = $InterSect | % {$_.Split(' ', 3)[2]}
                $To_Update = Compare-Object $Remote $InterSect -PassThru | % {$_.Split(' ', 3)[2]}
                if ($To_Update){
                    $To_BackUp = Compare-Object $To_Update $Local_FileName -PassThru -IncludeEqual -ExcludeDifferent
                }
                else{
                    $To_BackUp = $null
                    $To_Update = $null
                }
                $To_Inform = Compare-Object $Local_FileName $Intersect_FileName -PassThru  | ? {$Remote_FileName -NotContains $_} # {$_ -notin $Remote_FileName}
            }
            else{
                $To_Update = $Remote_FileName
                $To_BackUp = Compare-Object $Local_FileName $Remote_FileName -PassThru -IncludeEqual -ExcludeDifferent
                $To_Inform = $Local_FileName | ? {$Remote_FileName -NotContains $_} # {$_ -notin $Remote_FileName}
            }
        }
        else{
            $To_Update = $Remote_FileName
            $To_BackUp = $null
            $To_Inform = $null
        }
    }
        if ($DebugMe -eq 1) {
                write-host "To Update: $To_Update"
                write-host "To Backup: $To_Backup"
                write-host "To Inform: $To_Inform"
        }
        $return.ToUpdate = $To_Update
    $return.ToBackup = $To_BackUp
    $return.ToInform = $To_Inform
        return $return
}

#endregion


$ZabbixServer = Get_Zabbix_address
$Url_Base = 'http://' + $ZabbixServer.addr + '/files'
$Remote = Get_Remote_Files
$TS = Get_TimeStamp


if ($Remote -ne 0){# If we have detailes about remote repo, begin comparing
    $Local = Get_Local_Files
    $Result =  (Compare_Repos $Remote $Local)
    if($Result.ToInform){# Found difference between local and remote repo? sending data to zabb
        if ($DelMissing -eq 0) {
            $Info_Send = @()
            foreach ($f in $Result.ToInform){
                $InfoPath = $ZabbixServer.script + $f
                $Info_Send += @(@{'DeployError' = "File $InfoPath exists in the local script folder but not in repository."})
            }
            $SendData = @(@{$ZbxHostName = $Info_Send})
            Data_Send $SendData $ZabbixServer
        }
        elseif ($DelMissing -eq 1) {
            foreach ($f in $Result.ToInform) {
                if ($f -notmatch 'deploy_win.ps1') {
                    $DelPath = $ZabbixServer.script + $f
                    Remove-Item -Path $DelPath
                }
            }
        }
        else {
            $Info_Send += @(@{'DeployError' = "Passed invalid param for deleting missing scripts. Should be 1 for yes or 0 for no."})
            $SendData = @(@{$ZbxHostName = $Info_Send})
            Data_Send $SendData $ZabbixServer
            return 1
        }
    }
    if ($Result.ToBackup){
        foreach ($File in $Result.ToBackup){
            $BackUpPath = $ZabbixServer.script + '\deploy_backup' + $File
            $PathExist = Test-Path (Split-Path -Path $BackUpPath)
            if (!$PathExist){
                New-Item -ItemType directory (Split-Path -Path $BackUpPath) | Out-Null
            }
            $ItemToMove = $ZabbixServer.script + $File
            $FileName = (Get-Item $ItemToMove).Name + '_' + $TS + '.bak'
            Rename-Item $ItemToMove $FileName
            Move-Item ($ZabbixServer.script + (Split-Path -Path $File) + '\' + $FileName) (Split-Path -Path ($BackUpPath))
        }
    }
    if ($Result.ToUpdate){
                foreach ($File in $Result.ToUpdate){
                   Try{
                                $PutPath = $ZabbixServer.script + $File
                                $PathExist = Test-Path (Split-Path -Path $PutPath)
                                if (!$PathExist){
                                        New-Item -ItemType directory (Split-Path -Path $PutPath) | Out-Null
                                }
                                $DownloadUrl = $Url_Base + '/local_scripts_windows' + $File.Replace("\", "/")
                                $WebClient = New-Object System.Net.WebClient
                                $WebClient.DownloadFile($DownloadUrl, $PutPath)

                   }
                   Catch{
                                $BackUp = $File + '_' + $TS + '.bak'
                                $BackUpExist = Test-Path ($ZabbixServer.script + '\deploy_backup' + $BackUp)
                                if ($BackUpExist){
                                        Move-Item -Path ($ZabbixServer.script + '\deploy_backup' + $BackUp) -Destination ($ZabbixServer.script + '\deploy_backup' + $File) -Force
                                        Move-Item -Path ($ZabbixServer.script + '\deploy_backup' + $File) -Destination ($ZabbixServer.script + $File) -Force
                                }
                                $Info_Send = @(@{'DeployError' = "Error loading file $File from remote repo with error: $_.Exception"})
                                $SendData = @(@{$ZbxHostName = $Info_Send})
                                Data_send $SendData $ZabbixServer
                                $ErrorVar = 1
                        }
                }
        }
    if ($DelMissing -eq 1) {
                $RootFolder = $ZabbixServer.script
                Get-ChildItem -Path $RootFolder -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSIsContainer -and (Get-ChildItem -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { !$_.PSIsContainer }) -eq $null } | Remove-Item -Force -Recurse
        }
        if (!$Info_Send) {
        $Info_Send = @(@{'DeployError' = 0})
        $SendData = @(@{$ZbxHostName = $Info_Send})
        Data_send $SendData $ZabbixServer
    }
        Write-host $ErrorVar
}


else{# No data from remote host? send info to zabb
    $Info_Send = @(@{'DeployError' = 'No data from remote repo or empty response.'})
    $Send_Data = @(@{$ZbxHostName = $Info_Send})
    Data_Send $Send_Data $ZabbixServer
    write-host 1
}
