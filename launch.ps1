# DDI PowerShell Wrapper - launches subnet scans

# 0a)   Argument provided points to subnets text file
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]    
    [string]$SubnetFile,
    [Parameter(Mandatory=$true)]
    [string]$EmailContact,
    [Parameter(Mandatory=$true)]
    [string]$EmailSMTP,
    [Parameter(Mandatory=$true)]
    [string]$EmailFrom
)

# Example path provided
#$SubnetFile = "C:\Users\Administrator\Downloads\net.txt"

# 0b)   Test that subnet file exists before executing rest of script. 
# NOTE: Using underscores "_" in subnet filenames is crucial for outputting logs correctly. 
#       DO NOT USE "-" or "." in subnet filenames!!!
Write-Host "Initializing variables, validating subnet file exists..."
try {
    $SUBNET_FILENAME = (Get-Item $SubnetFile).Name
}
catch {
    Write-Output "ERROR:`tGiven subnet file not valid! Restart script supplying valid file"
    Exit 1
}

# 0c)   Deletes log file if it already exists
$LOGFILE = "$($SubnetFile | Split-Path | Split-Path)\logs\$($SUBNET_FILENAME.Split("-").Split(".")[1])_log.txt"
if (Test-Path -Path $LOGFILE) {
    Write-Host "Renewing log file..."
    Remove-Item -Path $LOGFILE
}

# 0d)   Append Nmap folder to the PATH variable, for one-time use
$folderToAdd = "C:\Program Files (x86)\Nmap\"
$originalPath = $env:PATH
$env:PATH = $originalPath + ";" + $folderToAdd



# 1a)   Run DDI script, using Python interpreter kept within DDI folder (has certain libs pre-loaded)
Write-Host "Executing python DDI scan script for $SUBNET_FILENAME..."
Set-Location -Path "C:\scripts\DDI\"
.\Scripts\python .\ddi -c .\config.json -a scan -s internal -u -f $SubnetFile | Out-File $LOGFILE

# 1b)   Parses log file for scanned subnet file, IP updates, & IP creations
$FILE_SCANNED = Get-Content -Path $LOGFILE | Select-Object -First 1
$LOGOUTPUT = Get-Content -Path $LOGFILE | Select-Object -Skip 1
$UPDATES = @(); $CREATIONS = @(); $ERROR_DETECTED = $false

if ($null -ne $FILE_SCANNED) {
    foreach ($l in $LOGOUTPUT) {
        if ($l -like "Updated*") {
            $UPDATES += $l.Substring(8)
        } elseif ($l -like "Created*") {
            $CREATIONS += $l.Substring(8)
        }
    }
} else {
    $ERROR_DETECTED = $true
}

# 2a)   Create Email Body / Variables
if ($ERROR_DETECTED) {
    # Make error message email body, if errors are detected
    $OUTPUT = $LOGOUTPUT
    $EMAIL_SUBJECT = "ERROR: DDI Scans - $($SUBNET_FILENAME.Split("-").Split(".")[1]) subnet"
} else {
    # Details a) IP creations or b) all IP's updated (w/ no creations)
    if ($CREATIONS.Count -eq 0) {
        $OUTPUT = 
        "Subnet File:`t$($FILE_SCANNED.Substring(5))`n`n" +
        "Updated IP's:`n$($UPDATES -join "`n")"
    } else {
        $OUTPUT = 
        "Subnet File:`t$($FILE_SCANNED.Substring(5))`n`n" +
        "Created (new) IP's:`n$($CREATIONS -join "`n")`n`n" +
        "Updated IP's:`n$($UPDATES -join "`n")"
    }

    $EMAIL_SUBJECT = "DDI Scans - $($SUBNET_FILENAME.Split("-").Split(".")[1]) subnet(s)"
}

# 2b)   Send output variable as email to contact, stop transcript
Write-Host "Preparing email to send log file contents..."
Send-MailMessage -SmtpServer $EmailSMTP -From $EmailFrom -To $EmailContact -Subject $EMAIL_SUBJECT -Body $($OUTPUT | Out-String)
Write-Host "SUCCESS:`tEmail sent to contact(s)!"