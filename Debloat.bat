@echo off
mode con cols=80 lines=30

powershell -Command "Write-Host ' [Removing] Bloatware Packages ' -F red -B black"
title [Removing 108 Bloatware Packages] [Trapped]

set listofbloatware=3DBuilder Automate Appconnector Microsoft3DViewer MicrosoftPowerBIForWindows MicrosoftPowerBIForWindows Print3D XboxApp GetHelp WindowsFeedbackHub BingFoodAndDrink BingHealthAndFitness BingTravel WindowsReadingList MixedReality.Portal ScreenSketch YourPhone PicsArt-PhotoStudio EclipseManager PolarrPhotoEditorAcademicEdition Wunderlist LinkedInforWindows AutodeskSketchBook Twitter DisneyMagicKingdoms MarchofEmpires ActiproSoftwareLLC Plex iHeartRadio FarmVille2CountryEscape Duolingo CyberLinkMediaSuiteEssentials DolbyAccess DrawboardPDF FitbitCoach Flipboard Asphalt8Airborne Keeper BingNews COOKINGFEVER PandoraMediaInc CaesarsSlotsFreeCasino Shazam PhototasticCollage TuneInRadio WinZipUniversal XING RoyalRevolt2 CandyCrushSodaSaga BubbleWitch3Saga CandyCrushSaga Getstarted bing MicrosoftOfficeHub OneNote WindowsPhone SkypeApp windowscommunicationsapps WindowsMaps Sway CommsPhone ConnectivityStore Hotspot Sketchable Clipchamp Prime TikTok ToDo Family NewVoiceNote SamsungNotes SamsungFlux StudioPlus SamsungWelcome SamsungQuickSearch SamsungPCCleaner SamsungCloudBluetoothSync PCGallery OnlineSupportSService HPJumpStarts HPPCHardwareDiagnosticsWindows HPPowerManager HPPrivacySettings HPSupportAssistant HPSureShieldAI HPSystemInformation HPQuickDrop HPWorkWell myHP HPDesktopSupportUtilities HPQuickTouch HPEasyClean HPSystemInformation MicrosoftTeams ACGMediaPlayer AdobePhotoshopExpress HiddenCity Hulu Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe MicrosoftSolitaireCollection MicrosoftStickyNotes Microsoft.People Microsoft.Wallet MinecraftUWP Todos Viber bingsports
(for %%a in (%listofbloatware%) do ( 
	set /a insidecount+=1
   PowerShell -Command "Get-AppxPackage -allusers *%%a* | Remove-AppxPackage"
))
powershell -Command "Write-Host ' [Removed] Bloatware Packages ' -F green -B black"

powershell -Command "Write-Host ' [Cleaning] Temp ' -F yellow -B black"
title [Cleaning Temp] [Trapped]
powershell -Command "Get-ChildItem -Path $env:TEMP -Include *.* -Exclude *.bat, *.lbool -File -Recurse | foreach { $_.Delete()}" >nul 2>nul
Del /S /F /Q %Windir%\Temp >nul 2>nul

powershell -Command "Write-Host ' [Cleaning] Windows Logs ' -F yellow -B black"
title [Cleaning Prefetch/Cache/Logs] [Trapped]
Del /S /F /Q %windir%\Prefetch >nul 2>nul

del %localappdata%\Yarn\Cache /F /Q /S >nul 2>nul

del %appdata%\Microsoft\Teams\Cache /F /Q /S >nul 2>nul

del %localappdata%\Microsoft\Windows\WebCache /F /Q /S >nul 2>nul

del "%SystemDrive%\*.log" /F /Q >nul 2>nul
del "%WinDir%\Directx.log" /F /Q >nul 2>nul
del "%WinDir%\SchedLgU.txt" /F /Q >nul 2>nul
del "%WinDir%\*.log" /F /Q >nul 2>nul
del "%WinDir%\security\logs\*.old" /F /Q >nul 2>nul
del "%WinDir%\security\logs\*.log" /F /Q >nul 2>nul
del "%WinDir%\Debug\*.log" /F /Q >nul 2>nul
del "%WinDir%\Debug\UserMode\*.bak" /F /Q >nul 2>nul
del "%WinDir%\Debug\UserMode\*.log" /F /Q >nul 2>nul
del "%WinDir%\*.bak" /F /Q >nul 2>nul
del "%WinDir%\system32\wbem\Logs\*.log" /F /Q >nul 2>nul
del "%WinDir%\OEWABLog.txt" /F /Q >nul 2>nul
del "%WinDir%\setuplog.txt" /F /Q >nul 2>nul
del "%WinDir%\Logs\DISM\*.log" /F /Q >nul 2>nul
del "%WinDir%\*.log.txt" /F /Q >nul 2>nul
del "%WinDir%\APPLOG\*.*" /F /Q >nul 2>nul
del "%WinDir%\system32\wbem\Logs\*.log" /F /Q >nul 2>nul
del "%WinDir%\system32\wbem\Logs\*.lo_" /F /Q >nul 2>nul
del "%WinDir%\Logs\DPX\*.log" /F /Q >nul 2>nul
del "%WinDir%\ServiceProfiles\NetworkService\AppData\Local\Temp\*.log" /F /Q >nul 2>nul
del "%WinDir%\Logs\*.log" /F /Q >nul 2>nul
del "%LocalAppData%\Microsoft\Windows\WindowsUpdate.log" /F /Q >nul 2>nul
del "%LocalAppData%\Microsoft\Windows\WebCache\*.log" /F /Q >nul 2>nul
del "%WinDir%\repair\setup.log" /F /Q >nul 2>nul
del "%WinDir%\Panther\UnattendGC\diagerr.xml" /F /Q >nul 2>nul
del "%WinDir%\Panther\UnattendGC\diagwrn.xml" /F /Q >nul 2>nul
del "%WinDir%\inf\setupapi.offline.log" /F /Q >nul 2>nul
del "%WinDir%\inf\setupapi.app.log" /F /Q >nul 2>nul
del "%WinDir%\debug\WIA\*.log" /F /Q >nul 2>nul
del "%SystemDrive%\PerfLogs\System\Diagnostics\*.*" /F /Q >nul 2>nul
del "%WinDir%\Logs\CBS\*.cab" /F /Q >nul 2>nul
del "%WinDir%\Logs\CBS\*.cab" /F /Q >nul 2>nul
del "%WinDir%\Logs\WindowsBackup\*.etl" /F /Q >nul 2>nul
del "%WinDir%\System32\LogFiles\HTTPERR\*.*" /F /Q >nul 2>nul
del "%WinDir%\SysNative\SleepStudy\*.etl" /F /Q >nul 2>nul
del "%WinDir%\SysNative\SleepStudy\ScreenOn\*.etl" /F /Q >nul 2>nul
del "%WinDir%\System32\SleepStudy\*.etl" /F /Q >nul 2>nul
del "%WinDir%\System32\SleepStudy\ScreenOn\*.etl" /F /Q >nul 2>nul
del "%WinDir%\Logs" /F /Q >nul 2>nul
del "%WinDir%\DISM" /F /Q >nul 2>nul

powershell -Command "Write-Host ' [Cleaning] Web Browsers Cache/Logs ' -F yellow -B black"
title [Cleaning Browsers Cache/Logs] [Trapped]

del "%LocalAppData%\Google\Chrome\User Data\Default\Cache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Google\Chrome\User Data\Default\Media Cache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Google\Chrome\User Data\Default\GPUCache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Google\Chrome\User Data\Default\Storage\ext" /F /Q /S >nul 2>nul
del "%LocalAppData%\Google\Chrome\User Data\Default\Service Worker" /F /Q /S >nul 2>nul
del "%LocalAppData%\Google\Chrome\User Data\ShaderCache" /F /Q /S >nul 2>nul


del "%LocalAppData%\Microsoft\Edge\User Data\Default\Cache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Media Cache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge\User Data\Default\GPUCache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Storage\ext" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge\User Data\Default\Service Worker" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge\User Data\ShaderCache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge SxS\User Data\Default\Cache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge SxS\User Data\Default\Media Cache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge SxS\User Data\Default\GPUCache" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge SxS\User Data\Default\Storage\ext" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge SxS\User Data\Default\Service Worker" /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Edge SxS\User Data\ShaderCache" /F /Q /S >nul 2>nul

del "%LocalAppData%\Opera Software\Opera Stable\cache" /F /Q /S >nul 2>nul
del "%AppData%\Opera Software\Opera Stable\GPUCache" /F /Q /S >nul 2>nul
del "%AppData%\Opera Software\Opera Stable\ShaderCache" /F /Q /S >nul 2>nul
del "%AppData%\Opera Software\Opera Stable\Jump List Icons" /F /Q /S >nul 2>nul
del "%AppData%\Opera Software\Opera Stable\Jump List IconsOld\Jump List Icons" /F /Q /S >nul 2>nul

del "%LocalAppData%\Vivaldi\User Data\Default\Cache" /F /Q /S >nul 2>nul

powershell -Command "Write-Host ' [Cleaning] Windows Defender Cache/Logs ' -F yellow -B black"
title [Cleaning Windows Defender Cache/Logs] [Trapped]

del "%ProgramData%\Microsoft\Windows Defender\Network Inspection System\Support\*.log" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Scans\History\CacheManager" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Scans\History\ReportLatency\Latency" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Scans\History\Service\*.log" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Scans\MetaStore" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Support" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Scans\History\Results\Quick" /F /Q /S >nul 2>nul
del "%ProgramData%\Microsoft\Windows Defender\Scans\History\Results\Resource" /F /Q /S >nul 2>nul

powershell -Command "Write-Host ' [Cleaning] Windows Font Cache ' -F yellow -B black"
title [Cleaning Windows Font Cache] [Trapped]

net stop FontCache >nul 2>nul
net stop FontCache3.0.0.0 >nul 2>nul
del "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*.dat" /F /Q /S >nul 2>nul
del "%WinDir%\SysNative\FNTCACHE.DAT" /F /Q /S >nul 2>nul
del "%WinDir%\System32\FNTCACHE.DAT" /F /Q /S >nul 2>nul
net start FontCache >nul 2>nul
net start FontCache3.0.0.0 >nul 2>nul

powershell -Command "Write-Host ' [Cleaning] Windows Icon Cache ' -F yellow -B black"
title [Cleaning  Windows Icon Cache] [Trapped]

%WinDir%\SysNative\ie4uinit.exe -show >nul 2>nul
%WinDir%\System32\ie4uinit.exe -show >nul 2>nul
del %LocalAppData%\IconCache.db /F /Q /S >nul 2>nul
del "%LocalAppData%\Microsoft\Windows\Explorer\iconcache_*.db" /F /Q /S >nul 2>nul

if exist %programdata%\ET\chck61.lbool del %programdata%\ET\chck61.lbool
title [/]>nul 2>nul
title [\]>nul 2>nul
title [/]>nul 2>nul
title [\]>nul 2>nul
title [/]>nul 2>nul
powershell -Command "Write-Host ' [Disabling] Xbox Services ' -F darkgray -B black"

title [Disabling Xbox Services] [Trapped]

sc config XblAuthManager start= disabled >nul 2>nul
sc config XboxNetApiSvc start= disabled >nul 2>nul
sc config XblGameSave start= disabled >nul 2>nul

powershell -Command "Write-Host ' [Disabling] Unnecessary Services ' -F darkgray -B black"

title [Disabling Unnecessary Services] [Trapped]

sc config ALG start=disabled >nul 2>nul
sc config AJRouter start=disabled >nul 2>nul
sc config WSearch start=disabled >nul 2>nul
sc config lfsvc start=disabled >nul 2>nul
sc config RemoteRegistry start=disabled >nul 2>nul
sc config WpcMonSvc start=disabled >nul 2>nul
sc config SEMgrSvc start=disabled >nul 2>nul
sc config SCardSvr start=disabled >nul 2>nul
sc config Netlogon start=disabled >nul 2>nul
sc config CscService start=disabled >nul 2>nul
sc config icssvc start=disabled >nul 2>nul
sc config wisvc start=disabled >nul 2>nul
sc config RetailDemo start=disabled >nul 2>nul
sc config WalletService start=disabled >nul 2>nul
sc config Fax start=disabled >nul 2>nul
sc config WbioSrvc start=disabled >nul 2>nul
sc config iphlpsvc start=disabled >nul 2>nul
sc config wcncsvc start=disabled >nul 2>nul
sc config fhsvc start=disabled >nul 2>nul
sc config PhoneSvc start=disabled >nul 2>nul
sc config seclogon start=disabled >nul 2>nul
sc config FrameServer start=disabled >nul 2>nul
sc config WbioSrvc start=disabled >nul 2>nul
sc config StiSvc start=disabled >nul 2>nul
sc config MapsBroker start=disabled >nul 2>nul
sc config bthserv start=disabled >nul 2>nul
sc config BDESVC start=disabled >nul 2>nul
sc config BthAvctpSvc start=disabled >nul 2>nul
sc config BthAvctpSvc start=disabledsc config BthAvctpSvc start=disabledsc config BthAvctpSvc start=disabledsc config BthAvctpSvc start=disabled >nul 2>nul
sc config CertPropSvc start=disabled >nul 2>nul
sc config WdiServiceHost start=disabled >nul 2>nul
sc config lmhosts start=disabled >nul 2>nul
sc config WdiSystemHost start=disabled >nul 2>nul
sc configTrkWks start=disabled >nul 2>nul
sc config WerSvc start=disabled >nul 2>nul
sc config TabletInputService start=disabled >nul 2>nul
sc config EntAppSvc start=disabled >nul 2>nul
sc config Spooler start=disabled >nul 2>nul
sc config BcastDVRUserService start=disabled >nul 2>nul
sc config WMPNetworkSvc start=disabled >nul 2>nul
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>nul
sc config DmEnrollmentSvc start=disabled >nul 2>nul
sc config PNRPAutoReg start=disabled >nul 2>nul
sc config wlidsvc start=disabled >nul 2>nul
sc config AXInstSV start=disabled >nul 2>nul
sc config lfsvc start=disabled >nul 2>nul
sc config rdyboost start=disabled >nul 2>nul
sc config themes start=disabled >nul 2>nul
sc config scardsvr start=disabled >nul 2>nul
sc config scdeviceenum start=disabled >nul 2>nul
sc config scpolicysvc start=disabled >nul 2>nul
sc config sensrsvc start=disabled >nul 2>nul
sc config sensordataservice start=disabled >nul 2>nul
sc config sensorservice start=disabled >nul 2>nul

powershell -Command "Write-Host ' [Disabling] Process Mitigations ' -F red -B black"

title [Disabling Process Mitigations] [Trapped]

powershell set-ProcessMitigation -System -Disable  DEP, EmulateAtlThunks, SEHOP, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy, StrictHandle, DisableWin32kSystemCalls, AuditSystemCall, DisableExtensionPoints, BlockDynamicCode, AllowThreadsToOptOut, AuditDynamicCode, CFG, SuppressExports, StrictCFG, MicrosoftSignedOnly, AllowStoreSignedBinaries, AuditMicrosoftSigned, AuditStoreSigned, EnforceModuleDependencySigning, DisableNonSystemFonts, AuditFont, BlockRemoteImageLoads, BlockLowLabelImageLoads, PreferSystem32, AuditRemoteImageLoads, AuditLowLabelImageLoads, AuditPreferSystem32, EnableExportAddressFilter, AuditEnableExportAddressFilter, EnableExportAddressFilterPlus, AuditEnableExportAddressFilterPlus, EnableImportAddressFilter, AuditEnableImportAddressFilter, EnableRopStackPivot, AuditEnableRopStackPivot, EnableRopCallerCheck, AuditEnableRopCallerCheck, EnableRopSimExec, AuditEnableRopSimExec, SEHOP, AuditSEHOP, SEHOPTelemetry, TerminateOnError, DisallowChildProcessCreation, AuditChildProcess >nul 2>nul       

powershell -Command "Write-Host ' [Disabling] Telemetry ' -F red -B black"

title [Disabling Telemetry] [Trapped]

sc config wdisystemhost start=disabled >nul 2>nul
sc config wdiservicehost start=disabled >nul 2>nul
sc config dssvc start=disabled >nul 2>nul
sc config dusmsvc start=disabled >nul 2>nul
sc config diagsvc start=disabled >nul 2>nul
sc config telemetry start=disabled >nul 2>nul
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>nul

powershell -Command "Write-Host ' [Adding] Latency Tweaks ' -F green -B black"

title [Adding Latency Tweaks] [Trapped]
echo Disable Dynamic Tick >nul 2>nul
echo Disable High Precision Event Timer (HPET) >nul 2>nul
echo Disable Synthetic Timers >nul 2>nul

bcdedit /set disabledynamictick yes >nul 2>nul
bcdedit /deletevalue useplatformclock >nul 2>nul
bcdedit /set useplatformtick yes >nul 2>nul


powershell -Command "Write-Host ' [Adding] Ping Tweaks ' -F green -B black"

title [Adding Ping Tweaks] [Trapped]

netsh int tcp set global autotuninglevel=normal >nul 2>nul
netsh interface 6to4 set state disabled >nul 2>nul
netsh int isatap set state disable >nul 2>nul
netsh int tcp set global timestamps=disabled >nul 2>nul
netsh int tcp set heuristics disabled >nul 2>nul
netsh int tcp set global chimney=disabled >nul 2>nul
netsh int tcp set global ecncapability=disabled >nul 2>nul
netsh int tcp set global rsc=disabled >nul 2>nul
netsh int tcp set global nonsackrttresiliency=disabled >nul 2>nul
netsh int tcp set security mpp=disabled >nul 2>nul
netsh int tcp set security profiles=disabled >nul 2>nul
netsh int ip set global icmpredirects=disabled >nul 2>nul
netsh int tcp set security mpp=disabled profiles=disabled >nul 2>nul
netsh int ip set global multicastforwarding=disabled >nul 2>nul
netsh int tcp set supplemental internet congestionprovider=ctcp >nul 2>nul
netsh interface teredo set state disabled >nul 2>nul
netsh winsock reset >nul 2>nul
netsh int isatap set state disable >nul 2>nul
netsh int ip set global taskoffload=disabled >nul 2>nul
netsh int ip set global neighborcachelimit=4096 >nul 2>nul
netsh int tcp set global dca=enabled >nul 2>nul
netsh int tcp set global netdma=enabled >nul 2>nul
PowerShell Disable-NetAdapterLso -Name "*" >nul 2>nul
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"  >nul 2>nul
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"  >nul 2>nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >nul 2>nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f >nul 2>nul

powershell -Command "Write-Host ' [Adding] Power Plan ' -F green -B black"

title [Adding Power Plan] [Trapped]

powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61  >nul 2>nul

set announcement=Everything has been complete. Computer Reset is Recomended
echo.
echo.
echo %b%             ╔══════════════════════════════════════════════════╗
echo %b%             ║                                                  ║
echo %b%             ║ %wh%%announcement% %b%║
echo %b%             ║                                                  ║
echo %b%             ╚══════════════════════════════════════════════════╝%wh%
echo.
echo.
powershell (New-Object -ComObject Wscript.Shell).Popup("""%announcement%""",0,"""%version%""",0x40 + 4096) >nul 2>nul
