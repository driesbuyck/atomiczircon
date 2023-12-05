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
    
        $startTimeString = $StartTime.ToUniversalTime().ToString("o")
        $endTimeString = $EndTime.ToUniversalTime().ToString("o")
        $query = "*[System[TimeCreated[@SystemTime >= '$startTimeString' and @SystemTime <= '$endTimeString']]]"
        Start-Process -FilePath "wevtutil" -ArgumentList "epl Security $logPath /q:`"$query`"" -NoNewWindow -Wait
        return $logPath
    } catch {
        Write-Error "Error exporting event logs: $_"
    }
}

function Export-RemoteEventLogs-Remote {
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
        $logFileName = "${logName}_$(Get-Date -Format 'yyyyMMddHHmmss').evtx"
        $logPath = Join-Path -Path $destinationPath -ChildPath $logFileName
        $query = "*[System[TimeCreated[@SystemTime >= '$startTime' and @SystemTime <= '$endTime']]]"
        wevtutil epl $logName $logPath /q:"$query"
        return $logPath
    }

    $remoteLogPath = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $StartTime, $EndTime, $LogName, $DestinationPath
    $localLogPath = Join-Path -Path $LocalPath -ChildPath (Split-Path -Leaf $remoteLogPath)

    # Copy the file from the remote path to the local path
    Copy-Item -Path $remoteLogPath -Destination $localLogPath -FromSession (New-PSSession -ComputerName $RemoteComputerName)
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
        $query = "*[System[TimeCreated[@SystemTime >= '$startTime' and @SystemTime <= '$endTime']]]"
        wevtutil epl $logName $logPath /q:"$query"
        return $logPath
    }

    # Try to export the log and get its remote path
    $remoteLogPath = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $StartTime, $EndTime, $LogName, $DestinationPath -ErrorAction Stop

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




# Record-TestResult function with improved output
function Record-TestResult {
    param (
        [string]$TestID,
        [string]$Results
    )
    Write-Host "Record test $TestID results: $Results"
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

# RunAtomicTest function refactored for clarity and robustness
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


function AppendToAtomicSigmaMap {
    param (
        [string]$ZircoliteSecurityOutput,
        [string]$ZircoliteSysmonOutput,
        [string]$ZircoliteSecurityRemoteOutput,
        [string]$TestID,
        [string]$TestName,
        [int]$ExitCode
    )

    $sigmaMapPath = Join-Path -Path $outputFolderPath -ChildPath "AtomicSigmaMap.csv"
    $includeColumns = @('rule_title', 'rule_level', 'rule_count', 'row_id', 'CommandLine')

    # Define a helper function to process each output
    function Process-ZircoliteOutput {
        param (
            [string]$OutputPath,
            [string]$LogSource,
            [string]$RemoteSource = $null  # Default to null
        )

        $zircoliteData = Import-Csv -Path $OutputPath -ErrorAction SilentlyContinue -Delimiter ';'
        if ($zircoliteData) {
            $zircoliteData | ForEach-Object {
                $properties = [ordered]@{
                    'TestID' = $TestID
                    'LogSource' = $LogSource
                    'RemoteSource' = $RemoteSource
                    'ExitCode' = $ExitCode
                    'TestName' = $TestName
                }
                foreach ($column in $_.PSObject.Properties) {
                    if ($includeColumns -contains $column.Name) {
                        $properties[$column.Name] = $column.Value
                    }
                }
                New-Object PSObject -Property $properties
            }
        }
        else {
            $emptyProperties = [ordered]@{
                'TestID' = $TestID
                'LogSource' = $LogSource
                'RemoteSource' = $RemoteSource
                'ExitCode' = $ExitCode
                'TestName' = $TestName
            }
            foreach ($column in $includeColumns) {
                $emptyProperties[$column] = $null
            }
            New-Object PSObject -Property $emptyProperties
        }
    }

    # Process each Zircolite output
    $outputs = @(
        @{ Path = $ZircoliteSecurityOutput; Source = 'SecurityEvents'; Remote = "LocalMachine" },
        @{ Path = $ZircoliteSysmonOutput; Source = 'Sysmon'; Remote = "LocalMachine" },
        @{ Path = $ZircoliteSecurityRemoteOutput; Source = 'SecurityEvents'; Remote = 'RemoteActiveDirectory' }
    )

    foreach ($output in $outputs) {
        Write-Host "Processing $output.Path with source $output.Source"
        $processedData = Process-ZircoliteOutput -OutputPath $output.Path -LogSource $output.Source -RemoteSource $output.Remote
        # Append or create CSV
        if (Test-Path -Path $sigmaMapPath) {
            $processedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation -Append
        } else {
            $processedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation
        }
    }
}


# Function to read test IDs from CSV

function Get-TestIdsFromCsv {
    param ([string]$CsvPath)
    $testTuples = New-Object System.Collections.Generic.List[Object]
    if (Test-Path -Path $CsvPath) {
        Import-Csv -Path $CsvPath | ForEach-Object {
            $tuple = [Tuple]::Create($_.ID, $_.Name)
            $testTuples.Add($tuple)
        }
    } else {
        Write-Error "CSV file not found at path: $CsvPath"
        return $null
    }
    return $testTuples
}

function Remove-FileIfExists {
    param (
        [string]$FilePath
    )

    if (Test-Path $FilePath) {
        Remove-Item $FilePath -Force
        Write-Host "File removed: $FilePath"
    } else {
        Write-Host "File does not exist: $FilePath"
    }
}






# Define folder paths
$processFolderPath = "$PSScriptRoot\process"
$outputFolderPath = "$PSScriptRoot\output"

# Create folders if they don't exist
if (-not (Test-Path -Path $processFolderPath)) {
    New-Item -ItemType Directory -Path $processFolderPath
}
if (-not (Test-Path -Path $outputFolderPath)) {
    New-Item -ItemType Directory -Path $outputFolderPath
}

#remove 
Remove-FileIfExists("output\AtomicSigmaMap.csv")

# Main execution loop with enhanced error handling
if ($testIdCsv) {
    # Get test IDs from CSV file
    # $testIDs = Get-TestIdsFromCsv -CsvPath $testIdCsv
    $testTuples = Get-TestIdsFromCsv -CsvPath $testIdCsv
 
}



foreach ($testTuple in $testTuples) {
    try {
        $testID = $testTuple.Item1
        $testName = $testTuple.Item2
        #Write-Host "DEBUG: TestID=$testID, TestName=$testName, Test: $test.keys"
        $results = RunAtomicTest -testID $testID
        $exitCode = $results[0]
        $zircoliteOutputs = $results[1]
        
        AppendToAtomicSigmaMap -ZircoliteSecurityOutput $zircoliteOutputs[0] -ZircoliteSysmonOutput $zircoliteOutputs[1] -ZircoliteSecurityRemoteOutput $zircoliteOutputs[2]  -TestID $testID -TestName $testName -ExitCode $exitCode
    } catch {
        Write-Error "Error in main execution loop for test ID ${testID}: $_"
    }
}

