<#
.SYNOPSIS
Automates running Atomic Red Team tests, exporting Windows event logs, processing them with Zircolite, and recording the results.

.DESCRIPTION
Runs specified Atomic Red Team tests, captures Windows 'Security' event log since the start of the test, processes the log with Zircolite, and records test results. Allows for optional debugging output from the Atomic Red Team test execution and displaying Zircolite output.

.PARAMETER testID
ID of the Atomic Red Team test to run (e.g., "T1003-1").

.PARAMETER ZircolitePath
File path to the Zircolite tool. Default is "C:\users\domainuser\tools\Zircolite-master\Zircolite-master".

.PARAMETER EnableDebug
A switch parameter. When provided, script captures and displays output from the Atomic Red Team test execution.

.PARAMETER ShowZircoliteOutput
A switch parameter. When provided, script displays the contents of the Zircolite output file.

.EXAMPLE
.\AtomicZircon.ps1 -testID "T1003-1" -EnableDebug -ShowZircoliteOutput

Runs Atomic Red Team test T1003-1 with debugging output enabled and displays the Zircolite output.

.EXAMPLE
.\AtomicZircon.ps1 -testID "T1003-2" -ZircolitePath "C:\CustomPath\Zircolite"

Runs Atomic Red Team test T1003-2 using Zircolite located at "C:\CustomPath\Zircolite".

.NOTES
Ensure Atomic Red Team and Zircolite tools are properly installed and accessible from the script.
#>

param (
    [Parameter(Mandatory=$true)]
    [string[]]$testIDs,  # Now accepts multiple test IDs

    [string]$ZircolitePath = "C:\users\domainuser\tools\Zircolite-master\Zircolite-master",

    [switch]$EnableDebug,

    [switch]$ShowZircoliteOutput,

    [int]$DelayInSeconds = 1  # Default delay of 1 second
)

function Export-EventLogs2 {
    param (
        [DateTime]$StartTime
    )
    $endTime = Get-Date
    $currentPath = Get-Location
    $logPath = "$currentPath\securityLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).csv"

    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$StartTime; EndTime=$endTime} |
        Export-Csv -Path $logPath -NoTypeInformation

    return $logPath
}

function Export-EventLogs {
    param (
        [DateTime]$StartTime
    )
    $endTime = Get-Date
    $currentPath = Get-Location
    $logPath = "$currentPath\securityLogs_$((Get-Date).ToString('yyyyMMddHHmmss')).evtx"

    # Format start and end times for the query
    $startTimeString = $StartTime.ToUniversalTime().ToString("o")  # Using the 'o' (round-trip) format specifier
    $endTimeString = $endTime.ToUniversalTime().ToString("o")

    # Constructing the query
    $query = "*[System[TimeCreated[@SystemTime >= '$startTimeString' and @SystemTime <= '$endTimeString']]]"

    # Constructing the full command
    $wevtutilCommand = "epl Security $logPath /q:`"$query`""

    # Using Start-Process to execute the wevtutil command
    Start-Process -FilePath "wevtutil" -ArgumentList $wevtutilCommand -NoNewWindow -Wait

    return $logPath
}




function Run-Zircolite {
    param (
        [string]$CsvPath,
        [switch]$EnableDebug  # Adding EnableDebug as a parameter to this function
    )
    $zircoliteOutput = "$PSScriptRoot\zircolite_scan.csv"

    $rulesPath = Join-Path -Path $ZircolitePath -ChildPath "rules\rules_windows_generic.json"

    if (Test-Path -Path $rulesPath) {
        $zircoliteScriptPath = Join-Path -Path $ZircolitePath -ChildPath "zircolite.py"
        $startProcessArgs = "`"$zircoliteScriptPath`" --evtx `"$CsvPath`" --csv --outfile `"$zircoliteOutput`" -r `"$rulesPath`""

        if ($EnableDebug) {
            Write-Host "Running Zircolite with the following command:"
            Write-Host "python $zircoliteScriptPath --evtx $CsvPath --csv --outfile $zircoliteOutput -r $rulesPath"
        }

        Start-Process -FilePath "python" -ArgumentList $startProcessArgs -Wait -WorkingDirectory $ZircolitePath
    } else {
        Write-Error "Zircolite rules file not found at path: $rulesPath"
    }

    # Additional Debug Information
    if ($EnableDebug -and (Test-Path $zircoliteOutput)) {
        Write-Host "Zircolite output file created at: $zircoliteOutput"
    } elseif ($EnableDebug) {
        Write-Host "Zircolite output file not found at: $zircoliteOutput"
    }

    return $zircoliteOutput
}




function Record-TestResult {
    param (
        [string]$TestID,
        [string]$Results
    )
    Write-Host "Record test $TestID results: $Results"
}

function Move-EventLogs {
    param (
        [string]$LogPath
    )
    $eventDataFolder = ".\eventdata"
    if (-not (Test-Path $eventDataFolder)) {
        New-Item -ItemType Directory -Path $eventDataFolder
    }
    Move-Item -Path $LogPath -Destination $eventDataFolder
}

function RunAtomicTest {
    param ([string]$testID)

    $startTime = Get-Date

    # Run prerequisites for the Atomic Test
    Invoke-Expression "Invoke-AtomicTest $testID -GetPrereqs"

    if ($EnableDebug) {
        $invokeResult = Invoke-Expression "Invoke-AtomicTest $testID" | Out-String
        Write-Host "Debug Output of Invoke-AtomicTest: `n$invokeResult"
    }
    else {
        Invoke-Expression "Invoke-AtomicTest $testID"
    }

    # Introduce a delay
    Start-Sleep -Seconds $DelayInSeconds
    Write-Host "Sleeping for $DelayInSeconds second(s)"

    $csvPath = Export-EventLogs -StartTime $startTime
    $zircoliteOutput = Run-Zircolite -CsvPath $csvPath

    Move-EventLogs -LogPath $csvPath

    Record-TestResult -TestID $testID -Results $zircoliteOutput

    if ($ShowZircoliteOutput) {
        Write-Host "`nZircolite Output:"
        Get-Content $zircoliteOutput
    }

    return $zircoliteOutput
}

function AppendToAtomicSigmaMap {
    param (
        [string]$ZircoliteOutput,
        [string]$TestID
    )
    $sigmaMapPath = "$PSScriptRoot\AtomicSigmaMap.csv"
    $zircoliteData = Import-Csv -Path $ZircoliteOutput -ErrorAction SilentlyContinue -Delimiter ';'

    # Define the list of columns to include from Zircolite output
    $includeColumns = @('rule_title','rule_level','rule_count','row_id','MandatoryLabel', 'CommandLine')

    if ($zircoliteData -ne $null) {
        $modifiedData = $zircoliteData | ForEach-Object {
            # Debugging: Print all column names in the current row
            #Write-Host "Columns in current row: $($_.PSObject.Properties.Name -join ', ')"
            
            $properties = [ordered]@{ 'TestID' = $TestID }
            foreach ($column in $_.PSObject.Properties) {
                if ($includeColumns -contains $column.Name) {
                    $properties[$column.Name] = $column.Value
                }
            }
            New-Object PSObject -Property $properties
        }

        # Additional debugging: print modified data
        Write-Host "Modified Data: $($modifiedData | Out-String)"

        # Check if AtomicSigmaMap.csv exists and either create or append to it
        if (Test-Path -Path $sigmaMapPath) {
            $modifiedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation -Append
        } else {
            $modifiedData | Export-Csv -Path $sigmaMapPath -NoTypeInformation
        }
    } else {
        Write-Host "No data found in Zircolite output file: $ZircoliteOutput"
    }
}


# Loop over each test ID and call RunAtomicTest for each one
foreach ($testID in $testIDs) {
    Write-Host "Running Atomic Test: $testID"
    $zircoliteOutput = RunAtomicTest -testID $testID

    # If you need to handle the output for each test separately, do it here
    # For example:
    AppendToAtomicSigmaMap -ZircoliteOutput $zircoliteOutput -TestID $testID
}




