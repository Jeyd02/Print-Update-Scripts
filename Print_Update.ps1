$os_ver = (Get-WmiObject Win32_OperatingSystem).version
if($os_ver -eq "10.0.14393"){
   # Executes on Windows 2016 Servers
   New-Item -Path C:\temp\patch\Default.txt -ItemType File -Force
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLU /t REG_DWORD /d 1 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
   curl.exe --insecure --ssl-no-revoke --url "http://download.windowsupdate.com/d/msdownload/update/software/secu/2021/07/windows10.0-kb5004948-x64_206b586ca8f1947fdace0008ecd7c9ca77fd6876.msu" -o "c:/temp/patch/kb5004948.msu"  
   Set-Service -Name "wuauserv" -StartupType Manual
   Start-Process -FilePath "wusa.exe" -ArgumentList "c:/temp/patch/kb5004948.msu /quiet /norestart" -Wait
   Reg Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f 
   Set-Service -Name "wuauserv" -status Stopped -StartupType Disabled 
   }
if($os_ver -eq "10.0.17763"){
   # Executes on 1809
   New-Item -Path C:\temp\patch\Default.txt -ItemType File -Force
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLU /t REG_DWORD /d 1 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
   curl.exe --insecure --ssl-no-revoke --url "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004947-x64_c00ea7cdbfc6c5c637873b3e5305e56fafc4c074.msu" -o "c:/temp/patch/kb5004947.msu"  
   Set-Service -Name "wuauserv" -StartupType Manual
   Start-Process -FilePath "wusa.exe" -ArgumentList "c:/temp/patch/kb5004947.msu /quiet /norestart" -Wait 
   Reg Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f 
   Set-Service -Name "wuauserv" -status Stopped -StartupType Disabled 
   }
if($os_ver -eq "10.0.18363"){
   # Executes on 1909
   New-Item -Path C:\temp\patch\Default.txt -ItemType File -Force
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLU /t REG_DWORD /d 1 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
   curl.exe --insecure --ssl-no-revoke --url "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004946-x64_ae43950737d20f3368f17f9ab9db28eccdf8cf26.msu" -o "c:/temp/patch/kb5004946.msu"
   Set-Service -Name "wuauserv" -StartupType Manual
   Start-Process -FilePath "wusa.exe" -ArgumentList "c:/temp/patch/kb5004946.msu /quiet /norestart" -Wait
   Reg Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f 
   Set-Service -Name "wuauserv" -status Stopped -StartupType Disabled 
   write-host("Your version is $os_ver")
   }
if($os_ver -eq "10.0.19041"){
   # Executes on 20H1
   New-Item -Path C:\temp\patch\Default.txt -ItemType File -Force
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLU /t REG_DWORD /d 1 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
   curl.exe --insecure --ssl-no-revoke --url "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004945-x64_db8eafe34a43930a0d7c54d6464ff78dad605fb7.msu" -o "c:/temp/patch/kb5004945.msu" 
   Set-Service -Name "wuauserv" -StartupType Manual
   Start-Process -FilePath "wusa.exe" -ArgumentList "c:/temp/patch/kb5004945.msu /quiet /norestart" -Wait
   Reg Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   Set-Service -Name "wuauserv" -status Stopped -StartupType Disabled  
   write-host("Your version is $os_ver")
   }
if($os_ver -eq "10.0.19042"){
   # Executes on 20H2
   New-Item -Path C:\temp\patch\Default.txt -ItemType File -Force
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLU /t REG_DWORD /d 1 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
   curl.exe --insecure --ssl-no-revoke --url "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004945-x64_db8eafe34a43930a0d7c54d6464ff78dad605fb7.msu" -o "c:/temp/patch/kb5004945.msu"
   Set-Service -Name "wuauserv" -StartupType Manual
   Start-Process -FilePath "wusa.exe" -ArgumentList "c:/temp/patch/kb5004945.msu /quiet /norestart" -Wait 
   Reg Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f 
   Set-Service -Name "wuauserv" -status Stopped -StartupType Disabled 
   write-host("Your version is $os_ver")
   }
if($os_ver -eq "10.0.19043"){
   #// Executes on 21H1
   New-Item -Path C:\temp\patch\Default.txt -ItemType File -Force
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLU /t REG_DWORD /d 1 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnInstall /t REG_DWORD /d 0 /f
   Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v NoWarningNoElevationOnUpdate /t REG_DWORD /d 0 /f
   curl.exe --insecure --ssl-no-revoke --url "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004945-x64_db8eafe34a43930a0d7c54d6464ff78dad605fb7.msu" -o "c:/temp/patch/kb5004945.msu" 
   Set-Service -Name "wuauserv" -StartupType Manual   
   Start-Process -FilePath "wusa.exe" -ArgumentList "c:/temp/patch/kb5004945.msu /quiet /norestart" -Wait 
   Reg Add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f 
   Set-Service -Name "wuauserv" -status Stopped -StartupType Disabled 
    }

