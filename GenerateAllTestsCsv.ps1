# Script to enumerate Atomic tests and save to CSV

# Invoke AtomicTest to get all tests
$atomicTestsOutput = Invoke-Expression "Invoke-AtomicTest ALL -ShowDetailsBrief"

# Extract tests and their names
$tests = $atomicTestsOutput -split "`r`n" | Where-Object { $_ -match "T\d+.*" }

# Parse tests to get ID and Name
$parsedTests = $tests | ForEach-Object {
    $id, $name = $_ -split ' ', 2
    [PSCustomObject]@{
        ID = $id.Trim()
        Name = $name.Trim()
    }
}

# Export to CSV
$parsedTests | Export-Csv -Path "AtomicTests.csv" -NoTypeInformation
