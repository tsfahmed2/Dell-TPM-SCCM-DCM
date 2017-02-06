$PSScriptRoot = ($MyInvocation.MyCommand.Path | Split-Path | Resolve-Path).ProviderPath
$BuildName = $PSScriptRoot | Split-Path -Leaf


#logging variables.
$logdir = "$($env:ALLUSERSPROFILE)\InstallLogs"
$Logfile = "$($logdir)\enable-tpm$(get-date -format `"yyyyMMdd_hhmmsstt`").log"
Function LogWrite($string, $color)
{
   if ($Color -eq $null) {$color = "white"}
   write-host $string -foregroundcolor $color
   $string | out-file -Filepath $logfile -append
}



if(!(Test-Path -Path $logdir )){
    New-Item -ItemType directory -Path $logdir
}


$tempdir = "$($env:SystemDrive)\temp"
if(!(Test-Path -Path $tempdir)){
    New-Item -ItemType directory -Path $tempdir
}



$cctkdir = "$($env:SystemDrive)\temp\Command Configure\X86_64"
$HAPIDIR = "$cctkdir\HAPI"
$cctkexe = "$cctkdir\cctk.exe"

<#

##################################################################################

Function Get-OSCTPMChip
{
<#
 	.SYNOPSIS
        Get-OSCTPMChip is an advanced function which can be list TPM chip status.
		
    .DESCRIPTION
        Get-OSCTPMChip is an advanced function which can be list TPM chip status.
		
	.PARAMETER	<ComputerName <string[]>
		Specifies the computers on which the command runs. The default is the local computer. 
		
	.PARAMETER  <Credential>
		Specifies a user account that has permission to perform this action. 
		
    .EXAMPLE
        C:\PS> Get-OSCTPMChip
		
		This command lists TPM chip status.
		
    .EXAMPLE
		C:\PS> $cre = Get-Credential
        C:\PS> Get-OSCFolderPermission -ComputerName "APP" -Credential $cre
		
		This command lists TPM chip status on the APP remote computer.
#>

<#
	[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Alias("CN")][String[]]$ComputerName=$Env:COMPUTERNAME,
		[Parameter(Mandatory=$false)]
		[Alias('Cred')][System.Management.Automation.PsCredential]$Credential
	)
	
	Foreach($CN in $ComputerName)
	{
		#test server connectivity
		$PingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
		If($PingResult)
		{
			If($Credential)
			{
				
				$TPMStatusInfo = Invoke-Command -ComputerName $CN -Credential $Credential `
				-ScriptBlock {Get-WmiObject -Class Win32_TPM -EnableAllPrivileges -Namespace "root\CIMV2\Security\MicrosoftTpm"}
				$TPMStatusInfo | Add-Member -Name ComputerName -Value $CN -MemberType NoteProperty
				$TPMStatusInfo | Select-Object ComputerName,IsActivated_InitialValue,IsEnabled_InitialValue,IsOwned_InitialValue,`
				ManufacturerId,ManufacturerVersion,ManufacturerVersionInfo,PhysicalPresenceVersionInfo,SpecVersion
			}
			Else
			{

				$TPMStatusInfo = Get-WmiObject -Class Win32_TPM -EnableAllPrivileges -Namespace "root\CIMV2\Security\MicrosoftTpm"
				$TPMStatusInfo | Add-Member -Name ComputerName -Value $CN -MemberType NoteProperty
				$TPMStatusInfo | Select-Object ComputerName,IsActivated_InitialValue,IsEnabled_InitialValue,IsOwned_InitialValue,`
				ManufacturerId,ManufacturerVersion,ManufacturerVersionInfo,PhysicalPresenceVersionInfo,SpecVersion
			}
		}
		Else
		{
			Write-Host "Cannot ping to $CN, please check the network connection"
		}
	}
}

#######################>
#>

$TPM = get-wmiobject win32_tpm -namespace "root/cimv2/security/microsofttpm"
$TPM
if(!$TPM){
    LogWrite "TPM is not present" blue
    (New-Object Net.WebClient).DownloadFile('https://fico.box.com/shared/static/dln7yonpq0j69yk34rvrqax0575y02u2.zip','C:\Temp\CommandConfigure.zip');(new-object -com shell.application).namespace('C:\temp').CopyHere((new-object -com shell.application).namespace('C:\temp\CommandConfigure.zip').Items(),16)
    if ($?)
    {

        $hapinstall = Start-Process "cmd.exe" "/c $HAPIDIR\HAPIInstall.bat" -Wait -PassThru
        LogWrite ""$hapinstall.ExitCode" hapinstall" red
        $setuppwd = Start-Process $cctkexe -args "--setuppwd=PASSWORD" -Wait -PassThru
        LogWrite ""$setuppwd.ExitCode" setuppwd" red
        $tpmon = Start-Process $cctkexe -args "--tpm=on --valsetuppwd=PASSWORD" -Wait -PassThru
        LogWrite ""$tpmon.ExitCode" tpm" red
        $tpmactivation = Start-Process $cctkexe -args "--tpmactivation=activate --valsetuppwd=PASSWORD" -Wait -PassThru
        LogWrite ""$tpmactivation.ExitCode" tpmactivation" red
    }
    else{
        LogWrite "Failed to download and unzip CCTK" red
    }
}
else {
    LogWrite "TPM present" red
}


###############################################