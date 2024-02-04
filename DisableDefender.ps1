#DISABLE DEFENDER SCRIPT BY ZOIC


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

function rename-file([String]$path){

if(Test-Path -LiteralPath "$PSScriptRoot\NSudoLG.exe"){
#rename file with trusted installer
if($path -like "*MsMpEng.exe*"){$newName = "MsMpEngOFF.exe"}
else{
$name, $extension = [System.IO.Path]::GetFileNameWithoutExtension($path), [System.IO.Path]::GetExtension($path)
$newName = "${name}OFF${extension}"
}
$arguments = "-U:T -P:E -M:S Powershell.exe -windowstyle Hidden -command `"Rename-Item -Path '$Path' -NewName $newName -Force`""

Start-Process "$PSScriptRoot\NSudoLG.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait 

}
else{

return "NSudo NOT Found!"

}





}


function Run-Nsudo([String]$path){

if(Test-Path -LiteralPath "$PSScriptRoot\NSudoLG.exe"){

$arguments = "-U:T -P:E -M:S `"$path`""
Start-Process "$PSScriptRoot\NSudoLG.exe" -ArgumentList $arguments -WindowStyle Hidden -Wait 

}
else{

return "NSudo NOT Found!"

}



}






if(!(Test-Path -LiteralPath "$PSScriptRoot\NSudoLG.exe")){
	#downloading nsudo to delete files protected by trusted installer
Invoke-RestMethod 'https://github.com/M2TeamArchived/NSudo/releases/download/9.0-Preview1/NSudo_9.0_Preview1_9.0.2676.0.zip' -OutFile "C:\Nsudo.zip"
Expand-Archive "C:\Nsudo.zip" -DestinationPath "C:\Nsudo"
Remove-Item "C:\Nsudo.zip" -Recurse -Force
Move-Item -LiteralPath "C:\Nsudo\x64\NSudoLG.exe" -Destination $PSScriptRoot -Force
#cleanup
Remove-Item -LiteralPath "C:\Nsudo" -Recurse -Force -ErrorAction SilentlyContinue
}





#disables defender through gp edit
Write-Host "Disabling Defender with Group Policy" 

#works: win 10
$file = New-Item -Path $env:TEMP -Name "DisableDefend.bat" -ItemType File -Force
$content = @"
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\WinDefend" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
Reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /t REG_DWORD /d 0 /f 

"@
Set-Content -Path $file -Value $content -Force
Run-Nsudo -path $file

#works: win10 and win11
$var = Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cache Maintenance'} | Disable-ScheduledTask
$var = Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cleanup'} | Disable-ScheduledTask 
$var = Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Scheduled Scan'} | Disable-ScheduledTask
$var = Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Verification'} | Disable-ScheduledTask
    

#apply gpedit tweaks

gpupdate /force


Write-Host "Disabling Services"

#disables antimalware service + core service

$imagePathValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "ImagePath"
$msMpEngPath = $imagePathValue.ImagePath 
rename-file -path $msMpEngPath

$WDPath = "C:\ProgramData\Microsoft\Windows Defender\Platform"
$corePaths = Get-ChildItem -Path $WDPath -Recurse -Filter "MpDefenderCoreService.exe" | ForEach-Object { $_.FullName }
$netPaths = Get-ChildItem -Path $WDPath -Recurse -Filter "NisSrv.exe" | ForEach-Object { $_.FullName } 


foreach($path in $corePaths){rename-file -path $path}
foreach($path in $netPaths){rename-file -path $path}
#disable smartscreen service
$smartScreen = "C:\Windows\System32\smartscreen.exe"
rename-file -path $smartScreen


#cleanup
Remove-Item -Path "$PSScriptRoot\NSudoLG.exe" -Force | Out-Null
Remove-Item -Path "$env:TEMP\DisableDefend.bat" -Force | Out-Null


[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  
Restart-Computer
 }

'No'{
}

}


