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


# Run-Zircolite function with better error handling and logging
function Run-Zircolite {
    param (
        [string]$SecurityLogPath,
        [string]$SysmonLogPath,
        [switch]$EnableDebug
    )
    try {

        $zircoliteOutputSecurity = Join-Path -Path $processFolderPath -ChildPath "zircolite_scan_security.csv"
        $zircoliteOutputSysmon = Join-Path -Path $processFolderPath -ChildPath "zircolite_scan_sysmon.csv"

        $rulesPathSecurity = Join-Path -Path $ZircolitePath -ChildPath "rules\rules_windows_generic.json"
        $rulesPathSysmon = Join-Path -Path $ZircolitePath -ChildPath "rules\rules_windows_sysmon.json"

        $zircoliteScriptPath = Join-Path -Path $ZircolitePath -ChildPath "zircolite.py"

        # Run Zircolite for Security Logs
        if (Test-Path -Path $rulesPathSecurity) {
            $startProcessArgsSecurity = "`"$zircoliteScriptPath`" --evtx `"$SecurityLogPath`" --csv --outfile `"$zircoliteOutputSecurity`" -r `"$rulesPathSecurity`""
            Start-Process -FilePath "python" -ArgumentList $startProcessArgsSecurity -Wait -WorkingDirectory $ZircolitePath
        } else {
            Write-Error "Security rules file not found at path: $rulesPathSecurity"
        }

        # Run Zircolite for Sysmon Logs
        if (Test-Path -Path $rulesPathSysmon) {
            $startProcessArgsSysmon = "`"$zircoliteScriptPath`" --evtx `"$SysmonLogPath`" --csv --outfile `"$zircoliteOutputSysmon`" -r `"$rulesPathSysmon`""
            Start-Process -FilePath "python" -ArgumentList $startProcessArgsSysmon -Wait -WorkingDirectory $ZircolitePath
        } else {
            Write-Error "Sysmon rules file not found at path: $rulesPathSysmon"
        }

        return $zircoliteOutputSecurity, $zircoliteOutputSysmon
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
        $securityLogPath = Export-EventLogs -StartTime $startTime -EndTime $endTime
        $sysmonLogPath = Export-SysmonLogs -StartTime $startTime -EndTime $endTime
        

        # Run Zircolite for both log types
        $zircoliteOutputs = Run-Zircolite -SecurityLogPath $securityLogPath -SysmonLogPath $sysmonLogPath -EnableDebug:$EnableDebug

        # Move logs and handle results
        Move-EventLogs -LogPath $securityLogPath
        Move-EventLogs -LogPath $sysmonLogPath # Assuming you have a similar mechanism for Sysmon logs

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


# AppendToAtomicSigmaMap function with improved logging
function AppendToAtomicSigmaMap {
    param (
        [string]$ZircoliteSecurityOutput,
        [string]$ZircoliteSysmonOutput,
        [string]$TestID,
        [string]$TestName,  # Add TestName parameter
        [int]$ExitCode
    )

    $sigmaMapPath = Join-Path -Path $outputFolderPath -ChildPath "AtomicSigmaMap.csv"
   
    # Process each Zircolite output
    foreach ($output in @{'Security'=$ZircoliteSecurityOutput; 'Sysmon'=$ZircoliteSysmonOutput}.GetEnumerator()) {
        $zircoliteData = Import-Csv -Path $output.Value -ErrorAction SilentlyContinue -Delimiter ';'
        $includeColumns = @('rule_title', 'rule_level', 'rule_count', 'row_id', 'CommandLine')

        if ($zircoliteData) {
            $modifiedData = $zircoliteData | ForEach-Object {
                $properties = [ordered]@{
                    'TestID' = $TestID
                    'TestName' = $TestName
                    'LogSource' = $output.Key  # Add log source column
                    'ExitCode' = $ExitCode
                }
                foreach ($column in $_.PSObject.Properties) {
                    if ($includeColumns -contains $column.Name) {
                        $properties[$column.Name] = $column.Value
                    }
                }

                #write-host "Properties (with zircoliteData): $properties"
                New-Object PSObject -Property $properties
            }


        }
        else{
            $properties = [ordered]@{
                'TestID' = $TestID
                'TestName' = $TestName
                'LogSource' = $output.Key
                'ExitCode' = $ExitCode
            }
            foreach ($column in $includeColumns) {
                $properties[$column] = $null  # Add empty values for other columns
            }
            write-host "Properties(without zircolite data): $properties"
            $modifiedData = New-Object PSObject -Property $properties
        }
        # Append or create CSV
        if (Test-Path -Path $sigmaMapPath) {
            $modifiedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation -Append
        } else {
            $modifiedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation
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
        
        AppendToAtomicSigmaMap -ZircoliteSecurityOutput $zircoliteOutputs[0] -ZircoliteSysmonOutput $zircoliteOutputs[1] -TestID $testID -TestName $testName -ExitCode $exitCode
    } catch {
        Write-Error "Error in main execution loop for test ID ${testID}: $_"
    }
}

