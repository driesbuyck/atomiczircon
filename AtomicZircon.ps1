param (
    [Parameter(Mandatory=$true)]
    [string[]]$testIDs,

    [string]$ZircolitePath = "C:\users\domainuser\tools\Zircolite-master\Zircolite-master",

    [switch]$EnableDebug,

    [switch]$ShowZircoliteOutput,

    [int]$DelayInSeconds = 1
)

# Improved Export-EventLogs function with added error handling and logging
function Export-EventLogs {
    param (
        [DateTime]$StartTime
    )
    try {
        $endTime = Get-Date
        $currentPath = Get-Location
        $logPath = "$currentPath\securityLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).evtx"
        $startTimeString = $StartTime.ToUniversalTime().ToString("o")
        $endTimeString = $endTime.ToUniversalTime().ToString("o")
        $query = "*[System[TimeCreated[@SystemTime >= '$startTimeString' and @SystemTime <= '$endTimeString']]]"
        Start-Process -FilePath "wevtutil" -ArgumentList "epl Security $logPath /q:`"$query`"" -NoNewWindow -Wait
        return $logPath
    } catch {
        Write-Error "Error exporting event logs: $_"
    }
}

# Run-Zircolite function with better error handling and logging
function Run-Zircolite {
    param (
        [string]$CsvPath,
        [switch]$EnableDebug
    )
    try {
        $zircoliteOutput = "$PSScriptRoot\zircolite_scan.csv"
        $rulesPath = Join-Path -Path $ZircolitePath -ChildPath "rules\rules_windows_generic.json"
        if (Test-Path -Path $rulesPath) {
            $zircoliteScriptPath = Join-Path -Path $ZircolitePath -ChildPath "zircolite.py"
            $startProcessArgs = "`"$zircoliteScriptPath`" --evtx `"$CsvPath`" --csv --outfile `"$zircoliteOutput`" -r `"$rulesPath`""
            Start-Process -FilePath "python" -ArgumentList $startProcessArgs -Wait -WorkingDirectory $ZircolitePath
        } else {
            Write-Error "Zircolite rules file not found at path: $rulesPath"
        }
        return $zircoliteOutput
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
        Invoke-Expression "Invoke-AtomicTest $testID -GetPrereqs"
        if ($EnableDebug) {
            $invokeResult = Invoke-Expression "Invoke-AtomicTest $testID" | Out-String
            Write-Host "Debug Output of Invoke-AtomicTest: `n$invokeResult"
        } else {
            Invoke-Expression "Invoke-AtomicTest $testID"
        }
        Start-Sleep -Seconds $DelayInSeconds
        $csvPath = Export-EventLogs -StartTime $startTime
        $zircoliteOutput = Run-Zircolite -CsvPath $csvPath -EnableDebug:$EnableDebug
        Move-EventLogs -LogPath $csvPath
        Record-TestResult -TestID $testID -Results $zircoliteOutput
        if ($ShowZircoliteOutput) {
            Write-Host "`nZircolite Output:"
            Get-Content $zircoliteOutput
        }
        return $zircoliteOutput
    } catch {
        Write-Error "Error running Atomic Test ${testID}: $_"
    }
}

# AppendToAtomicSigmaMap function with improved logging
function AppendToAtomicSigmaMap {
    param (
        [string]$ZircoliteOutput,
        [string]$TestID
    )
    try {
        $sigmaMapPath = "$PSScriptRoot\AtomicSigmaMap.csv"
        $zircoliteData = Import-Csv -Path $ZircoliteOutput -ErrorAction SilentlyContinue -Delimiter ';'
        $includeColumns = @('rule_title','rule_level','rule_count','agg','row_id','MandatoryLabel', 'CommandLine')
        if ($zircoliteData) {
            $modifiedData = $zircoliteData | ForEach-Object {
                $properties = [ordered]@{ 'TestID' = $TestID }
                foreach ($column in $_.PSObject.Properties) {
                    if ($includeColumns -contains $column.Name) {
                        $properties[$column.Name] = $column.Value
                    }
                }
                New-Object PSObject -Property $properties
            }
            if (Test-Path -Path $sigmaMapPath) {
                $modifiedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation -Append
            } else {
                $modifiedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation
            }
        } else {
            Write-Host "No data found in Zircolite output file: $ZircoliteOutput"
        }
    } catch {
        Write-Error "Error appending to Atomic Sigma Map: $_"
    }
}

# Main execution loop with enhanced error handling
foreach ($testID in $testIDs) {
    try {
        $zircoliteOutput = RunAtomicTest -testID $testID
        AppendToAtomicSigmaMap -ZircoliteOutput $zircoliteOutput -TestID $testID
    } catch {
        Write-Error "Error in main execution loop for test ID ${testID}: $_"
    }
}
