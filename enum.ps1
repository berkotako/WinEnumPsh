Write-Host "Host informaiton:------------" -ForegroundColor Green  #USER ID  msn1WT5msdXJ8Vra4XBkDyM6Yzt1 -- Write a Windows host enumeration program
Get-Host 
Write-Host "Host Name:-------------" -ForegroundColor Green
(Get-WMIObject win32_operatingsystem).name
Write-Host "OS Arch:------------" -ForegroundColor Green
(Get-WMIObject win32_operatingsystem).OSArchitecture
Write-Host "CSName:-----------" -ForegroundColor Green
(Get-WMIObject win32_operatingsystem).CSName
Write-Host "OS Version:----------" -ForegroundColor Green
(Get-WMIObject win32_operatingsystem).Version
Write-Host "Users:----------" -ForegroundColor Green
Get-LocalUser 
Write-Host "İnstalled Softwares:----------" -ForegroundColor Green
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize
Write-Host "---------------------------------------------------" -ForegroundColor Green
Write-Host "Proxy Settings:----------" -ForegroundColor Green
Get-ItemProperty -Path ("Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
Write-Host "PuTTy Sesions:----------" -ForegroundColor Green
$sessions = Get-ChildItem 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
[array]$properties = @('HostName','TerminalType','TerminalSpeed')

Write-Host "Listing PuTTy sessions" -ForegroundColor Green 
foreach ($session in $sessions) {
    
    $name       = ($session.Name.Substring($session.Name.LastIndexOf("\") + 1)).Replace("%20"," ")
    Write-Host $name -ForegroundColor White
    
    Foreach ($property in $properties) {
                
        Write-Host -NoNewLine `t $property":" -ForegroundColor Green
        Write-Host $session.GetValue($property)
        
        }

    Write-Host "---------------------------"
    
}
$objUser = New-Object System.Security.Principal.NTAccount("berkk") # You must change Administrator to find which user you want.
$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
Write-Host "SID VALUE:" $strSID.Value
Write-Host "PuTTy SSH Keys" -ForegroundColor Green 
$file_name="Registry::HKEY_USERS\"+($strSID.Value)+"\Software\SimonTatham\PuTTY\SshHostKeys\" 
Get-ItemProperty -Path $file_name
Write-Host "PuTTy Recent Sessions" -ForegroundColor Green
$file_name="Registry::HKEY_USERS\"+($strSID.Value)+"\Software\SimonTatham\PuTTY\Jumplist\"
Get-ItemProperty -Path $file_name
Write-Host "Command History" -ForegroundColor Green 
Get-History
Write-Host "RDP Sessions" -ForegroundColor Green
qwinsta.exe
