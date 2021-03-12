# On-Prem AKS Demo

## Requirements
This guide is written to be installed on a Windows 10 updated host running > 20H2
It assumes powershell 5 or 7 will be used, to check your version: 

```powershell
get-host | select-object version
```

## Hyper-V
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

## RESTART
You'll need to restart at this point! 

```batch
shutdown /r /t 0
```

```powershell
New-VMSwitch -Name "InternalNAT" -SwitchType Internal
New-NetIPAddress -IPAddress 192.168.0.1 -PrefixLength 24 -InterfaceAlias "vEthernet (InternalNAT)"
New-NetNat -Name "AzSHCINAT" -InternalIPInterfaceAddressPrefix 192.168.0.0/24
Get-NetNat

Set-VMhost -EnableEnhancedSessionMode $True

New-Item -Path "C:\" -Name "ISO" -ItemType "directory"
```

>> TODO: not working
```powershell
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
Stop-Process -Name Explorer
```

# Download the files
Next, in order to download the ISO files, open your web browser and follow the steps below.

## Server 2019
Visit https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019, complete the registration form, and download the ISO. Save the file as WS2019.iso to C:\ISO

## Windows 10
Visit https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise, complete the registration form, and download the x64 ISO. Save the file as W10.iso to C:\ISO

## Azure Stack HCI 
Visit https://azure.microsoft.com/en-us/products/azure-stack/hci/hci-download, complete the registration form, and download the ISO. Save the file as AzSHCI.iso to C:\ISO

## Windows Admin Center
Visit https://aka.ms/wacdownload to download the executables for the Windows Admin Center. Save it as WindowsAdminCenter.msi, also in C:\ISO


## Check that all content is present and named correctly
```powershell 
Get-ChildItem -Path C:\ISO
```

## Output

```batch
    Directory: C:\ISO


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          2/4/2021   6:15 PM     3559997440 AzSHCI.iso
-a----          2/4/2021   6:13 PM     5296713728 W10.iso
-a----          2/4/2021   6:07 PM       72638464 WindowsAdminCenter.msi
-a----          2/4/2021   6:16 PM     5588209664 WS2019.iso
```

# Create DC01 VM
>> Note: FAILS IF FILE EXISTS

```powershell
New-VM -Name "DC01" -MemoryStartupBytes 4GB -SwitchName "InternalNAT" -Path "C:\VMs\" -NewVHDPath "C:\VMs\DC01\Virtual Hard Disks\DC01.vhdx" -NewVHDSizeBytes 30GB -Generation 2
```

## Dynamic Memory Allocation
Allow the VM to only use the memory required, and free it up otherwise. 

```powershell
Set-VMMemory DC01 -DynamicMemoryEnabled $true -MinimumBytes 1GB -StartupBytes 4GB -MaximumBytes 4GB
```

## Add ISO to VM
```powershell
$DVD = Add-VMDvdDrive -VMName DC01 -Path C:\ISO\WS2019.iso -Passthru
Set-VMFirmware -VMName DC01 -FirstBootDevice $DVD
Set-VM -VMName DC01 -CheckpointType Disabled
Set-VM -VMName DC01 –AutomaticStartAction Start

```

# Start VM
```powershell
vmconnect.exe localhost DC01
Start-Sleep -Seconds 5 # Just gives enough time to see the "Press any key..." message
Start-VM -Name DC01

```

# Configure AD

# Provide a password for the VM that you set in the previous step

```powershell
$dcCreds = Get-Credential -UserName "Administrator" -Message "Enter the password used when you deployed Windows Server 2019"
Invoke-Command -VMName "DC01" -Credential $dcCreds -ScriptBlock {
    New-NetIPAddress -IPAddress "192.168.0.2" -DefaultGateway "192.168.0.1" -InterfaceAlias "Ethernet" -PrefixLength "24" | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("1.1.1.1")
    $dcIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object IPAddress
    Write-Verbose "The currently assigned IPv4 address for DC01 is $($dcIP.IPAddress)" -Verbose 
    Write-Verbose "Updating Hostname for DC01" -Verbose
    Rename-Computer -NewName "DC01"
}

Write-Verbose "Rebooting DC01 for hostname change to take effect" -Verbose
Stop-VM -Name DC01
Start-Sleep -Seconds 5
Start-VM -Name DC01

while ((Invoke-Command -VMName DC01 -Credential $dcCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "DC01 is now online. Proceed to the next step...." -Verbose

```

# Update the Server 

```powershell
Invoke-Command -VMName "DC01" -Credential $dcCreds -ScriptBlock {
    $ScanResult = Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" `
    -MethodName ScanForUpdates -Arguments @{SearchCriteria = "IsInstalled=0" }

    if ($ScanResult.Updates) {
        Invoke-CimMethod -Namespace "root/Microsoft/Windows/WindowsUpdate" -ClassName "MSFT_WUOperations" `
        -MethodName InstallUpdates -Arguments @{Updates = $ScanResult.Updates }
    }
}

Write-Verbose "Rebooting DC01 to finish installing updates" -Verbose
Stop-VM -Name DC01
Start-Sleep -Seconds 5
Start-VM -Name DC01

# Test for the DC01 to be back online and responding
while ((Invoke-Command -VMName DC01 -Credential $dcCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "DC01 is now online. Proceed to the next step...." -Verbose

```

# Configure AD

```powershell
Invoke-Command -VMName DC01 -Credential $dcCreds -ScriptBlock {
    # Set the Directory Services Restore Mode password
    $DSRMPWord = ConvertTo-SecureString -String "Password01" -AsPlainText -Force
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainMode 7 `
        -DomainName "azshci.local" `
        -ForestMode 7 `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $DSRMPWord `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$true `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true
}
Write-Verbose "Rebooting DC01 to finish installing of Active Directory" -Verbose
Stop-VM -Name DC01
Start-Sleep -Seconds 5
Start-VM -Name DC01

# Set updated domain credentials based on previous credentials
$domainName = "azshci.local"
$domainAdmin = "$domainName\administrator"
$domainCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $domainAdmin, $dcCreds.Password

# Test for the DC01 to be back online and responding
while ((Invoke-Command -VMName DC01 -Credential $domainCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "DC01 is now online. Proceed to the next step...." -Verbose
Write-Verbose "Creating new administrative User within the azshci.local domain." -Verbose
$newUser = "LabAdmin"
Invoke-Command -VMName DC01 -Credential $domainCreds -ScriptBlock {
    Write-Verbose "Waiting for AD Web Services to be in a running state" -Verbose
    $ADWebSvc = Get-Service ADWS | Select-Object *
    while ($ADWebSvc.Status -ne 'Running') {
        Start-Sleep -Seconds 1
    }
    Do {
        Start-Sleep -Seconds 30
        Write-Verbose "Waiting for AD to be Ready for User Creation" -Verbose
        New-ADUser -Name $using:newUser -AccountPassword $using:domainCreds.Password -Enabled $True
        $ADReadyCheck = Get-ADUser -Identity $using:newUser
    }
    Until ($ADReadyCheck.Enabled -eq "True")
    Add-ADGroupMember -Identity "Domain Admins" -Members $using:newUser
    Add-ADGroupMember -Identity "Enterprise Admins" -Members $using:newUser
    Add-ADGroupMember -Identity "Schema Admins" -Members $using:newUser
}
Write-Verbose "$newUser Account Created." -Verbose

```

# Create Windows 10 VM

```powershell
New-VM `
    -Name "MGMT01" `
    -MemoryStartupBytes 4GB `
    -SwitchName "InternalNAT" `
    -Path "C:\VMs\" `
    -NewVHDPath "C:\VMs\MGMT01\Virtual Hard Disks\MGMT01.vhdx" `
    -NewVHDSizeBytes 127GB `
    -Generation 2
Set-VMMemory MGMT01 -DynamicMemoryEnabled $true -MinimumBytes 2GB -StartupBytes 4GB -MaximumBytes 4GB
$DVD = Add-VMDvdDrive -VMName MGMT01 -Path C:\ISO\W10.iso -Passthru
Set-VMFirmware -VMName MGMT01 -FirstBootDevice $DVD
# Disable checkpoints
Set-VM -VMName MGMT01 -CheckpointType Disabled
vmconnect.exe localhost MGMT01
Start-Sleep -Seconds 5
Start-VM -Name MGMT01
```

# Win 10 Networking
```powershell
# Define local Windows 10 credentials
$w10Creds = Get-Credential -UserName "LocalAdmin" -Message "Enter the password used when you deployed Windows 10"
Invoke-Command -VMName "MGMT01" -Credential $w10Creds -ScriptBlock {
    # Set Static IP on MGMT01
    New-NetIPAddress -IPAddress "192.168.0.3" -DefaultGateway "192.168.0.1" -InterfaceAlias "Ethernet" -PrefixLength "24" | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.2")
    $mgmtIP = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet" | Select-Object IPAddress
    Write-Verbose "The currently assigned IPv4 address for MGMT01 is $($mgmtIP.IPAddress)" -Verbose 
}

```

# Join Win 10 to Domain

```powershell
# Define domain-join credentials
$domainName = "azshci.local"
$domainAdmin = "$domainName\labadmin"
$domainCreds = Get-Credential -UserName "$domainAdmin" -Message "Enter the password for the LabAdmin account"
Invoke-Command -VMName "MGMT01" -Credential $w10Creds -ScriptBlock {
    # Rename and join domain
    Add-Computer -DomainName azshci.local -NewName "MGMT01" -Credential $using:domainCreds -Force
}

Write-Verbose "Rebooting MGMT01 for hostname change to take effect" -Verbose
Stop-VM -Name MGMT01
Start-Sleep -Seconds 5
Start-VM -Name MGMT01

# Test for the MGMT01 to be back online and responding
while ((Invoke-Command -VMName MGMT01 -Credential $domainCreds {"Test"} -ErrorAction SilentlyContinue) -ne "Test") {
    Start-Sleep -Seconds 1
}
Write-Verbose "MGMT01 is now online. Proceed to the next step...." -Verbose

```

# Install Windows Admin Center

```
vmconnect.exe localhost MGMT01

```

# On Windows Admin Center Host

```powershell
set-item wsman:localhost\client\trustedhosts -value *

Enable-WSManCredSSP -Role Client –DelegateComputer *
```

Then install admin center via GUI...

# Create First Azure Stack HCI Node

```powershell
$nodeName = "AZSHCINODE01"
$newIP = "192.168.0.4"
New-VM `
    -Name $nodeName  `
    -MemoryStartupBytes 40GB `
    -SwitchName "InternalNAT" `
    -Path "C:\VMS-NEW\" `
    -NewVHDPath "C:\VMS-NEW\$nodeName\Virtual Hard Disks\$nodeName.vhdx" `
    -NewVHDSizeBytes 30GB `
    -Generation 2
Set-VMMemory -VMName $nodeName -DynamicMemoryEnabled $false
# Add the DVD drive, attach the ISO to DC01 and set the DVD as the first boot device
$DVD = Add-VMDvdDrive -VMName $nodeName -Path C:\ISO\AzSHCI.iso -Passthru
Set-VMFirmware -VMName $nodeName -FirstBootDevice $DVD
# Set the VM processor count for the VM
Set-VM -VMname $nodeName -ProcessorCount 16
# Add the virtual network adapters to the VM and configure appropriately
1..3 | ForEach-Object { 
    Add-VMNetworkAdapter -VMName $nodeName -SwitchName InternalNAT
    Set-VMNetworkAdapter -VMName $nodeName -MacAddressSpoofing On -AllowTeaming On 
}
# Create the DATA virtual hard disks and attach them
$dataDrives = 0..9 | ForEach-Object { New-VHD -Path "C:\VMS-NEW\$nodeName\Virtual Hard Disks\DATA0$_.vhdx" -Dynamic -Size 100GB }
$dataDrives | ForEach-Object {
    Add-VMHardDiskDrive -Path $_.path -VMName $nodeName
}
# Disable checkpoints
Set-VM -VMName $nodeName -CheckpointType Disabled
# Enable nested virtualization
Set-VMProcessor -VMName $nodeName -ExposeVirtualizationExtensions $true -Verbose
vmconnect.exe localhost $nodeName
Start-Sleep -Seconds 5
Start-VM -Name $nodeName

```

# Configure the First Node from the Host OS

```powershell
# Define local credentials
$azsHCILocalCreds = Get-Credential -UserName "Administrator" -Message "Enter the password used when you deployed the Azure Stack HCI 20H2 OS"
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

# Provide the domain credentials to log into the VM
$domainName = "azshci.local"
$domainAdmin = "$domainName\labadmin"
$domainCreds = Get-Credential -UserName "$domainAdmin" -Message "Enter the password for the LabAdmin account"
Invoke-Command -VMName $nodeName -Credential $domainCreds -ScriptBlock {
    # Enable the Hyper-V role within the Azure Stack HCI 20H2 OS
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
    # Enable the Hyper-V PowerShell within the Azure Stack HCI 20H2 OS
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
```

# Prepare the _Second_ Azure Stack HCI Node

```powershell
$nodeName = "AZSHCINODE02"
$newIP = "192.168.0.5"
New-VM `
    -Name $nodeName  `
    -MemoryStartupBytes 40GB `
    -SwitchName "InternalNAT" `
    -Path "C:\VMS-NEW\" `
    -NewVHDPath "C:\VMS-NEW\$nodeName\Virtual Hard Disks\$nodeName.vhdx" `
    -NewVHDSizeBytes 30GB `
    -Generation 2
Set-VMMemory -VMName $nodeName -DynamicMemoryEnabled $false
# Add the DVD drive, attach the ISO to DC01 and set the DVD as the first boot device
$DVD = Add-VMDvdDrive -VMName $nodeName -Path C:\ISO\AzSHCI.iso -Passthru
Set-VMFirmware -VMName $nodeName -FirstBootDevice $DVD
# Set the VM processor count for the VM
Set-VM -VMname $nodeName -ProcessorCount 16
# Add the virtual network adapters to the VM and configure appropriately
1..3 | ForEach-Object { 
    Add-VMNetworkAdapter -VMName $nodeName -SwitchName InternalNAT
    Set-VMNetworkAdapter -VMName $nodeName -MacAddressSpoofing On -AllowTeaming On 
}
# Create the DATA virtual hard disks and attach them
$dataDrives = 0..9 | ForEach-Object { New-VHD -Path "C:\VMS-NEW\$nodeName\Virtual Hard Disks\DATA0$_.vhdx" -Dynamic -Size 100GB }
$dataDrives | ForEach-Object {
    Add-VMHardDiskDrive -Path $_.path -VMName $nodeName
}
# Disable checkpoints
Set-VM -VMName $nodeName -CheckpointType Disabled
# Enable nested virtualization
Set-VMProcessor -VMName $nodeName -ExposeVirtualizationExtensions $true -Verbose
vmconnect.exe localhost $nodeName
Start-Sleep -Seconds 5
Start-VM -Name $nodeName

```

# Configure the _Second_ Node from the Host OS

```powershell
# Define local credentials
$azsHCILocalCreds = Get-Credential -UserName "Administrator" -Message "Enter the password used when you deployed the Azure Stack HCI 20H2 OS"
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
    # Enable the Hyper-V role within the Azure Stack HCI 20H2 OS
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
    # Enable the Hyper-V PowerShell within the Azure Stack HCI 20H2 OS
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
```

# Set Up a _Single Node_ Windows 2019 Datacenter Node

```powershell
$nodeName = "WIN2019NODE01"
$newIP = "192.168.0.6"
New-VM `
    -Name $nodeName  `
    -MemoryStartupBytes 40GB `
    -SwitchName "InternalNAT" `
    -Path "C:\VMS-NEW\" `
    -NewVHDPath "C:\VMS-NEW\$nodeName\Virtual Hard Disks\$nodeName.vhdx" `
    -NewVHDSizeBytes 600GB `
    -Generation 2
Set-VMMemory -VMName $nodeName -DynamicMemoryEnabled $false
# Add the DVD drive, attach the ISO to DC01 and set the DVD as the first boot device
$DVD = Add-VMDvdDrive -VMName $nodeName -Path C:\ISO\WS2019.iso -Passthru
Set-VMFirmware -VMName $nodeName -FirstBootDevice $DVD
# Set the VM processor count for the VM
Set-VM -VMname $nodeName -ProcessorCount 16

# Add the virtual network adapters to the VM and configure appropriately
#1..3 | ForEach-Object { 
#    Add-VMNetworkAdapter -VMName $nodeName -SwitchName InternalNAT
#    Set-VMNetworkAdapter -VMName $nodeName -MacAddressSpoofing On -AllowTeaming On 
#}
# Disable checkpoints
#Set-VM -VMName $nodeName -CheckpointType Disabled

# Enable nested virtualization
Set-VMProcessor -VMName $nodeName -ExposeVirtualizationExtensions $true -Verbose
vmconnect.exe localhost $nodeName
Start-Sleep -Seconds 5
Start-VM -Name $nodeName

```
Install the GUI version, once it reboots, set the admin password, then login.

Make sure to both turn on network sharing as well as share the C drive and turn off the firewall for now (AKS setup assumes C drive is accessible as admin share over the network).

>> TODO: lock perms down to only what's needed. 

# Configure the _Only_ Server 2019 Node from the Host OS

```powershell
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
```

# On Server 2019 DC Host

## IPv6
You'll need to turn off IPv6 so that the external switch gets an internal IP. 


## Set up vswitch and CredSSP
```powershell
Set-VMhost -EnableEnhancedSessionMode $True
New-VMSwitch -name aks2019ext -NetAdapterName Ethernet -AllowManagementOs $true
New-NetIPAddress -IPAddress 192.168.1.1 -PrefixLength 24 -InterfaceAlias "vEthernet (ExternalNAT)"
New-NetNat -Name "AKS2019NAT" -InternalIPInterfaceAddressPrefix 192.168.1.0/24
Get-NetNat
Enable-WSManCredSSP -Role Server

```

## WinRM
You'll also need to allow WinRM remoting from untrusted hosts: https://appuals.com/how-to-fix-issues-connecting-to-remote-hyper-v-server-2019/
Computer Settings > Administrative Templates > System > Credentials Delegation
Double click on Allow delegating fresh credentials with NTLM-only server authentication
Activate policy by clicking on Enable
Click Show… next to Add servers to the list
Click on the field and type WSMAN/Hyper-V Server name. In our example server is called hyperv01, so we will type wsman/mgmt01

gpupdate /force

# Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Conemu
choco install conemu

# Windows Terminal
choco install -y microsoft-windows-terminal

# Vagrant

choco install -y vagrant vagrant-winrm-config packer

# Unattended Installs

https://taylor.dev/how-to-create-an-automated-install-for-windows-server-2019/


# Choco one-liner
choco install -y conemu microsoft-windows-terminal vagrant vagrant-winrm-config packer vim wsl2

# Install Datadog Beta on VMs and Host

```powershell
$ProgressPreference = 'SilentlyContinue'
wget "https://s3.amazonaws.com/ddagent-windows-unstable/datadog-agent-7.23.2-beta1-1-x86_64.msi" -usebasicparsing -outfile .\ddagent.msi
Start-Process -Wait msiexec -ArgumentList '/i ddagent.msi'
$ProgressPreference = 'Continue'

```

```powershell
choco install -ia="APIKEY=""YOUR_DATADOG_API_KEY""" datadog-agent

```

# Stable DD Release

```powershell
$ProgressPreference = 'SilentlyContinue'
wget "https://s3.amazonaws.com/ddagent-windows-stable/datadog-agent-7-latest.amd64.msi" -usebasicparsing -outfile .\ddagent.msi 
Start-Process -Wait msiexec -ArgumentList '/i ddagent.msi'
$ProgressPreference = 'Continue'

```

# Export Windows Admin Center Connections

```powershell
# Load the module
Import-Module "$env:ProgramFiles\windows admin center\PowerShell\Modules\ConnectionTools"
# Available cmdlets: Export-Connection, Import-Connection

# Export connections (including tags) to a .csv file
Export-Connection "https://wac.contoso.com" -fileName "WAC-connections.csv"

```

# Import Windows Admin Center Connections
Note that this snippet assumes that `WAC-connections.csv` is in the current path. 

```powershell
# Import connections (including tags) from a .csv file
Import-Connection "https://wac.contoso.com" -fileName "WAC-connections.csv"

```


# ARC
choco install -y git
git clone https://github.com/microsoft/azure_arc.git
cd azure_arc

# Troubleshooting

## VM Doesn't Restart After Install
Sometimes the VM for the node won't come up after the install, just reboot it. 

## WinRM after AKS install

Connecting to remote server win2019node01.azshci.local failed with the following error message : The WinRM client cannot process the request. 

A computer policy does not allow the delegation of the user credentials to the target computer because the computer is not trusted. 

The identity of the target computer can be verified if you configure the WSMAN service to use a valid certificate using the following command: winrm set winrm/config/service '@{CertificateThumbprint="<thumbprint>"}' 

Or you can check the Event Viewer for an event that specifies that the following SPN could not be created: WSMAN/<computerFQDN>.

wsman/*
wsman/*.azshci.local

 If you find this event, you can manually create the SPN using setspn.exe . 
 
 If the SPN exists, but CredSSP cannot use Kerberos to validate the identity of the target computer and you still want to allow the delegation of the user credentials to the target computer, use gpedit.msc and look at the following policy: Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Fresh Credentials with NTLM-only Server Authentication. Verify that it is enabled and configured with an SPN appropriate for the target computer. For example, for a target computer name "myserver.domain.com", the SPN can be one of the following: WSMAN/myserver.domain.com or WSMAN/*.domain.com. Try the request again after these changes. For more information, see the about_Remote_Troubleshooting Help topic.

## Grab Updated Powershell

`https://github.com/PowerShell/PowerShell/releases/tag/v7.1.1
`

## WSL

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

## grab update 

```powershell
Invoke-WebRequest -uri https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi -OutFile wslupdate.msi -UseBasicParsing
msiexec.exe /i wslupdate.msi
wsl --set-default-version 2
```

## Download Ubuntu 16 for WSL from: https://docs.microsoft.com/en-us/windows/wsl/install-manual

```powershell
Invoke-WebRequest -Uri https://aka.ms/wslubuntu2004 -OutFile Ubuntu.appx -UseBasicParsing
Add-AppxPackage .\Ubuntu.appx
```
