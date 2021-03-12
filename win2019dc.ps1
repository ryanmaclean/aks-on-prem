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
