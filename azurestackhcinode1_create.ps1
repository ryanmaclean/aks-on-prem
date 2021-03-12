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
