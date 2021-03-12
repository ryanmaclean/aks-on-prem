# Define local credentials
$azsHCILocalCreds = Get-Credential -UserName "Administrator" -Message "Enter the password used when you deployed the Windows Server 2019 DC OS"
# Refer to earlier in the script for $nodeName and $newIP
Invoke-Command -VMName $nodeName -Credential $azsHCILocalCreds -ScriptBlock {
    # Set Static IP
    New-NetIPAddress -IPAddress "$using:newIP" -DefaultGateway "192.168.0.1" -InterfaceAlias "Ethernet" -PrefixLength "24" | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.2")
    $nodeIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object IPAddress
    Write-Verbose "The currently assigned IPv4 address for $using:nodeName is $($nodeIP.IPAddress)" -Verbose 
}
# Define domain-join credentials
$domainName = "azshci.local"
$domainAdmin = "$domainName\labadmin"
$domainCreds = Get-Credential -UserName "$domainAdmin" -Message "Enter the password for the LabAdmin account"
Invoke-Command -VMName $nodeName -Credential $azsHCILocalCreds -ArgumentList $domainCreds -ScriptBlock {
    # Change the name and join domain
    Rename-Computer -NewName $Using:nodeName -LocalCredential $Using:azsHCILocalCreds -Force -Verbose
    Start-Sleep -Seconds 5
    Add-Computer -DomainName "azshci.local" -Credential $Using:domainCreds -Force -Options JoinWithNewName,AccountCreate -Restart -Verbose
}

# Test for the node to be back online and responding
while ((Invoke-Command -VMName $nodeName -Credential $domainCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
    Write-Host "Waiting for server to come back online"
}
Write-Verbose "$nodeName is now online. Proceed to the next step...." -Verbose

Invoke-Command -VMName $nodeName -Credential $domainCreds -ScriptBlock {
    # Enable the Hyper-V role within the Windows Server 2019 DC OS
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart -Verbose
}

Write-Verbose "Rebooting node for changes to take effect" -Verbose
Stop-VM -Name $nodeName
Start-Sleep -Seconds 5
Start-VM -Name $nodeName

# Test for the node to be back online and responding
while ((Invoke-Command -VMName $nodeName -Credential $domainCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "$nodeName is now online. Proceeding to install Hyper-V PowerShell...." -Verbose

Invoke-Command -VMName $nodeName -Credential $domainCreds -ScriptBlock {
    # Enable the Hyper-V PowerShell within the Windows Server 2019 DC OS
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart -Verbose
}

Write-Verbose "Rebooting node for changes to take effect" -Verbose
Stop-VM -Name $nodeName
Start-Sleep -Seconds 5
Start-VM -Name $nodeName

# Test for the node to be back online and responding
while ((Invoke-Command -VMName $nodeName -Credential $domainCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "$nodeName is now online. Proceed to the next step...." -Verbose
