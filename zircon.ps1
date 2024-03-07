param (
    [Parameter(Mandatory=$false)]
    [string[]]$testIDs,

    [string]$ZircolitePath = "C:\users\domainuser\tools\Zircolite-master\Zircolite-master",

    [switch]$EnableDebug,

    [switch]$ShowZircoliteOutput,

    [int]$DelayInSeconds = 1,

    [string]$testIdCsv  # New parameter for specifying the CSV file
)



# Improved Export-EventLogs function with added error handling and logging
function Export-EventLogs {
    param (
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )
    try {
        $currentPath = Get-Location
        #$logPath = "$currentPath\SecurityLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).evtx"
        $logPath = Join-Path -Path $processFolderPath -ChildPath "SecurityLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).evtx"
        Write-Host "Logpath: $logPath"
        $startTimeString = $StartTime.ToUniversalTime().ToString("o")
        $endTimeString = $EndTime.ToUniversalTime().ToString("o")
        $query = "*[System[TimeCreated[@SystemTime >= '$startTimeString' and @SystemTime <= '$endTimeString']]]"
        Write-Host "Building query: $query"
        Start-Process -FilePath "wevtutil" -ArgumentList "epl Security $logPath /q:`"$query`"" -NoNewWindow -Wait
        Write-Host "Ending the process of exporting"
        return $logPath
    } catch {
        Write-Error "Error exporting local event logs: $_"
    }
}

function Export-RemoteEventLogs {
    param (
        [string]$RemoteComputerName,
        [DateTime]$StartTime,
        [DateTime]$EndTime,
        [string]$LogName = 'Security',
        [string]$DestinationPath,
        [string]$LocalPath  # Local path to save the file
    )

    $scriptBlock = {
        param($startTime, $endTime, $logName, $destinationPath)
        $logFileName = "${logName}_AD_$(Get-Date -Format 'yyyyMMddHHmmss').evtx"
        $logPath = Join-Path -Path $destinationPath -ChildPath $logFileName
        Write-Host "Logpath: $logPath"
        $query = "*[System[TimeCreated[@SystemTime >= '$startTime' and @SystemTime <= '$endTime']]]"
        wevtutil epl $logName $logPath /q:"$query"
        return $logPath
    }

    # Try to export the log and get its remote path
    $remoteLogPath = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $StartTime, $EndTime, $LogName, $DestinationPath -ErrorAction Stop
    Write-Host "Logpath: $remoteLogPath"
    if ($remoteLogPath) {
        $localLogPath = Join-Path -Path $LocalPath -ChildPath (Split-Path -Leaf $remoteLogPath)
        # Copy the file from the remote path to the local path
        $session = New-PSSession -ComputerName $RemoteComputerName
        Copy-Item -Path $remoteLogPath -Destination $localLogPath -FromSession $session
        Remove-PSSession $session
    } else {
        Write-Error "Failed to export log from remote computer."
    }
    return $localLogPath
}

function Export-SysmonLogs {
    param (
        [DateTime]$StartTime,
        [DateTime]$EndTime
    )
    try {
        $currentPath = Get-Location
        #$logPath = "$currentPath\SysmonLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).evtx"
        $logPath = Join-Path -Path $processFolderPath -ChildPath "SecurityLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).evtx"
        Write-Host "Logpath: $logPath"
        # Format start and end times for the query
        $startTimeString = $StartTime.ToUniversalTime().ToString("o")
        $endTimeString = $EndTime.ToUniversalTime().ToString("o")

        # Constructing the query
        $query = "*[System[TimeCreated[@SystemTime >= '$startTimeString' and @SystemTime <= '$endTimeString']]]"

        # Export Sysmon logs
        wevtutil epl "Microsoft-Windows-Sysmon/Operational" $logPath /q:"$query"

        return $logPath
    } catch {
        Write-Error "Error exporting Sysmon logs: $_"
    }
}

function Run-Zircolite {
    param (
        [string]$SecurityLogPath,
        [string]$SysmonLogPath,
        [string]$SecurityRemoteLogPath,
        [switch]$EnableDebug
    )
    try {
        # Define output paths for Zircolite scan results
        $zircoliteOutputSecurity = Join-Path -Path $processFolderPath -ChildPath "zircolite_scan_security.csv"
        $zircoliteOutputSysmon = Join-Path -Path $processFolderPath -ChildPath "zircolite_scan_sysmon.csv"
        $zircoliteOutputSecurityRemote = Join-Path -Path $processFolderPath -ChildPath "zircolite_scan_security_remote.csv"

        # Paths to Zircolite rules
        $rulesPathSecurity = Join-Path -Path $ZircolitePath -ChildPath "rules\rules_windows_generic.json"
        $rulesPathSysmon = Join-Path -Path $ZircolitePath -ChildPath "rules\rules_windows_sysmon.json"

        # Zircolite script path
        $zircoliteScriptPath = Join-Path -Path $ZircolitePath -ChildPath "zircolite.py"

        # Function to run Zircolite for a given log file
        function Process-LogFile {
            param (
                [string]$LogFilePath,
                [string]$OutputPath,
                [string]$RulesPath
            )
            if (Test-Path -Path $LogFilePath) {
                $startProcessArgs = "`"$zircoliteScriptPath`" --evtx `"$LogFilePath`" --csv --outfile `"$OutputPath`" -r `"$RulesPath`""
                Start-Process -FilePath "python" -ArgumentList $startProcessArgs -Wait -WorkingDirectory $ZircolitePath
            } else {
                Write-Warning "Log file not found or path is invalid: $LogFilePath"
            }
        }

        # Process each log file with Zircolite, if the path is valid
        if ($SecurityLogPath) { Process-LogFile -LogFilePath $SecurityLogPath -OutputPath $zircoliteOutputSecurity -RulesPath $rulesPathSecurity }
        if ($SysmonLogPath) { Process-LogFile -LogFilePath $SysmonLogPath -OutputPath $zircoliteOutputSysmon -RulesPath $rulesPathSysmon }
        if ($SecurityRemoteLogPath) { Process-LogFile -LogFilePath $SecurityRemoteLogPath -OutputPath $zircoliteOutputSecurityRemote -RulesPath $rulesPathSecurity }

        return $zircoliteOutputSecurity, $zircoliteOutputSysmon, $zircoliteOutputSecurityRemote
    } catch {
        Write-Error "Error running Zircolite: $_"
    }
}

function Move-EventLogs {
    param (
        [string]$LogPath
    )
    try {
        $eventDataFolder = ".\eventdata"
        if (-not (Test-Path $eventDataFolder)) {
            New-Item -ItemType Directory -Path $eventDataFolder
        }
        Write-Host "Moving file $LogPath to .\eventdata"
        Move-Item -Path $LogPath -Destination $eventDataFolder
        
    } catch {
        Write-Error "Error moving event logs: $_"
    }
}

function RunAtomicTest {
    param ([string]$testID)
    try {
        $startTime = Get-Date
        Start-Sleep -Seconds $DelayInSeconds

        # Run prerequisites and the test
        Invoke-Expression "Invoke-AtomicTest $testID -GetPrereqs"
        if ($EnableDebug) {
            $invokeResult = Invoke-Expression "Invoke-AtomicTest $testID" | Out-String
            Write-Host "Debug Output of Invoke-AtomicTest: `n$invokeResult"
        } else {
            Invoke-Expression "Invoke-AtomicTest $testID"
        }
        $exitCode = $LASTEXITCODE  # Capture the exit code

        Start-Sleep -Seconds $DelayInSeconds

        # Export Security and Sysmon logs
        $endTime = Get-Date
        Write-Host "Exporting EventLogs"
        $securityLogPath = Export-EventLogs -StartTime $startTime -EndTime $endTime
        try {
            # The code that attempts the remote connection
            Write-Host "Exporting Remote EventLogs"
            $securityRemoteLogPath = Export-RemoteEventLogs -RemoteComputerName "AD2019-2ND" -StartTime $startTime -EndTime $endTime -LogName "Security" -DestinationPath "C:\\Users\\Public" -LocalPath "C:\users\domainuser\programming\atomiczircon"
        } catch {
            # Custom error handling for remote connection issues
            Write-Host "Failed to connect to remote server 'AD2019-2ND'."
            Write-Host "Error: $_"
            Write-Host "Please ensure the server is reachable and that your credentials are correct."
            Write-Host "Check if Kerberos authentication and WinRM configurations are set up properly."
            # You can choose to return or continue based on your requirements
            
        }
        Write-Host "Exporting SysmonLogs"
        $sysmonLogPath = Export-SysmonLogs -StartTime $startTime -EndTime $endTime
        

        # Run Zircolite for both log types
        #$zircoliteOutputs = Run-Zircolite -SecurityLogPath $securityLogPath -SysmonLogPath $sysmonLogPath -EnableDebug:$EnableDebug
        Write-Host "Running zircolite"
        Write-Host "On files \n- $securityLogPath\n- $sysmonLogPath\n- $securityRemoteLogPath"
        $zircoliteOutputs = Run-Zircolite -SecurityLogPath $securityLogPath -SysmonLogPath $sysmonLogPath -SecurityRemoteLogPath $securityRemoteLogPath -EnableDebug:$EnableDebug

        # Move logs and handle results
        
        Move-EventLogs -LogPath $securityLogPath
        Move-EventLogs -LogPath $sysmonLogPath # Assuming you have a similar mechanism for Sysmon logs
        if ($securityRemoteLogPath){
            Move-EventLogs -LogPath $securityRemoteLogPath
        }

        Record-TestResult -TestID $testID -Results $zircoliteOutputs

        if ($ShowZircoliteOutput) {
            Write-Host "`nZircolite Security Log Output:"
            Get-Content $zircoliteOutputs[0]
            Write-Host "`nZircolite Sysmon Log Output:"
            Get-Content $zircoliteOutputs[1]
        }

        return $exitCode, $zircoliteOutputs 
    } catch {
        Write-Error "Error running Atomic Test ${testID}: $_"
    }
}
# Move-EventLogs function with error handling
function Move-EventLogs {
    param (
        [string]$LogPath
    )
    try {
        $eventDataFolder = ".\eventdata"
        if (-not (Test-Path $eventDataFolder)) {
            New-Item -ItemType Directory -Path $eventDataFolder
        }
        Write-Host "Moving file $LogPath to .\eventdata"
        Move-Item -Path $LogPath -Destination $eventDataFolder
        
    } catch {
        Write-Error "Error moving event logs: $_"
    }
}

function Record-TestResult {
    param (
        [string]$TestID,
        [string]$Results
    )
    Write-Host "Record test $TestID results: $Results"
}

# Define folder paths
$processFolderPath = "$PSScriptRoot\process"
$outputFolderPath = "$PSScriptRoot\output"
RunAtomicTest -testID T1195