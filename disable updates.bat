@echo off
:: Minimize self if cmdow is present (optional, suppresses UI early)
:: Uncomment the next line if you have cmdow.exe in the same directory
:: cmdow @ /MIN

:: Auto elevate to Admin
if not "%1"=="admin" (
    powershell -WindowStyle Hidden -Command "Start-Process '%~f0' -ArgumentList 'admin' -Verb RunAs"
    exit /b
)

:: Auto elevate to SYSTEM
if not "%2"=="system" (
    powershell -WindowStyle Hidden -Command "Start-Process '%~dp0\PsExec.exe' -ArgumentList '/accepteula -i -s -d \"%~f0\" admin system' -Verb RunAs"
    exit /b
)

:: Disable update related services
for %%i in (wuauserv, UsoSvc, uhssvc, WaaSMedicSvc) do (
    net stop %%i
    sc config %%i start= disabled
    sc failure %%i reset= 0 actions= ""
)

:: Brute force rename services
for %%i in (WaaSMedicSvc, wuaueng) do (
    takeown /f C:\Windows\System32\%%i.dll && icacls C:\Windows\System32\%%i.dll /grant *S-1-1-0:F
    rename C:\Windows\System32\%%i.dll %%i_BAK.dll
    icacls C:\Windows\System32\%%i_BAK.dll /setowner "NT SERVICE\TrustedInstaller" && icacls C:\Windows\System32\%%i_BAK.dll /remove *S-1-1-0
)

:: Update registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v FailureActions /t REG_BINARY /d 000000000000000000000000030000001400000000000000c0d4010000000000e09304000000000000000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f

:: Delete downloaded update files
erase /f /s /q c:\windows\softwaredistribution\*.* && rmdir /s /q c:\windows\softwaredistribution

:: Disable all update related scheduled tasks
powershell -WindowStyle Hidden -Command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\InstallService\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateAssistant\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WaaSMedic\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\WindowsUpdate\*' | Disable-ScheduledTask"

:: Done - exit silently
echo Finished.
timeout /t 1 >nul
exit
