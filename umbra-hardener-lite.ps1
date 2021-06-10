# ---------------------------------------------------------------------------------------------------------------------
#
#
# Author: Daechir
# Author URL: https://github.com/daechir
# Modified Date: 06/09/21
# Version: v1c
#
#
# ---------------------------------------------------------------------------------------------------------------------
#
#
# Changelog:
#		v1c
#			* Fix the majority of inaccessible areas in the ImmersiveControlPanel (Settings app).
#			* Add system restore point tweaks.
#			* Add some basic firewall rules.
#
#
# ---------------------------------------------------------------------------------------------------------------------


function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

function CreateLog ($logname,$functionname) {
	$logfile = $PSScriptRoot + "\logs\" + $logname
	$functionname = "Now logging for function: " + $functionname + "`n`n"

	New-Item -Force $logfile

	Add-Content -Path $logfile -Value $functionname

	Start-Transcript -Path $logfile -Append
}

function StopLog {
	Stop-Transcript
}

function SysCleanup {
	# Bloatware app cleanup
	# AppxPackage(s)
	$apps = @(
		# Microsoft apps
		"Microsoft.3DBuilder"
		"Microsoft.AppConnector"
		"Microsoft.BingFinance"
		"Microsoft.BingFoodAndDrink"
		"Microsoft.BingHealthAndFitness"
		"Microsoft.BingMaps"
		"Microsoft.BingNews"
		"Microsoft.BingSports"
		"Microsoft.BingTranslator"
		"Microsoft.BingTravel"
		"Microsoft.BingWeather"
		"Microsoft.CommsPhone"
		"Microsoft.ConnectivityStore"
		"Microsoft.FreshPaint"
		"Microsoft.GetHelp"
		"Microsoft.Getstarted"
		"Microsoft.HelpAndTips"
		"Microsoft.Media.PlayReadyClient.2"
		"Microsoft.Messaging"
		"Microsoft.Microsoft3DViewer"
		"Microsoft.MicrosoftOfficeHub"
		"Microsoft.MicrosoftPowerBIForWindows"
		"Microsoft.MicrosoftSolitaireCollection"
		"Microsoft.MicrosoftStickyNotes"
		"Microsoft.MinecraftUWP"
		"Microsoft.MixedReality.Portal"
		"Microsoft.MoCamera"
		"Microsoft.MSPaint"
		"Microsoft.NetworkSpeedTest"
		"Microsoft.News"
		"Microsoft.Office.Lens"
		"Microsoft.Office.OneNote"
		"Microsoft.Office.Sway"
		"Microsoft.Office.Todo.List"
		"Microsoft.OfficeLens"
		"Microsoft.OneConnect"
		"Microsoft.People"
		"Microsoft.Print3D"
		"Microsoft.Reader"
		"Microsoft.RemoteDesktop"
		"Microsoft.ScreenSketch"
		"Microsoft.SkypeApp"
		"Microsoft.StorePurchaseApp"
		"Microsoft.Todos"
		"Microsoft.Wallet"
		"Microsoft.WebMediaExtensions"
		"Microsoft.Whiteboard"
		"Microsoft.Windows.Photos"
		"Microsoft.WindowsAlarms"
		"Microsoft.WindowsCamera"
		"Microsoft.windowscommunicationsapps"
		"Microsoft.WindowsFeedbackHub"
		"Microsoft.WindowsMaps"
		"Microsoft.WindowsPhone"
		"Microsoft.WindowsReadingList"
		"Microsoft.WindowsScan"
		"Microsoft.WindowsSoundRecorder"
		"Microsoft.WinJS.1.0"
		"Microsoft.WinJS.2.0"
		"Microsoft.Xbox.TCUI"
		"Microsoft.XboxApp"
		"Microsoft.XboxGameCallableUI"
		"Microsoft.XboxGameOverlay"
		"Microsoft.XboxGamingOverlay"
		"Microsoft.XboxIdentityProvider"
		"Microsoft.XboxSpeechToTextOverlay"
		"Microsoft.YourPhone"
		"Microsoft.ZuneMusic"
		"Microsoft.ZuneVideo"

		# Microsoft store
		"Microsoft.DesktopAppInstaller"
		"Microsoft.Services.Store.Engagement"
		"Microsoft.StorePurchaseApp"
		"Microsoft.WindowsStore"

		# Microsoft.Advertising.Xaml - Called last due to dependency errors
		"Microsoft.Advertising.Xaml"

		# Third party apps
		"4DF9E0F8.Netflix"
		"7EE7776C.LinkedInforWindows"
		"9E2F88E3.Twitter"
		"828B5831.HiddenCityMysteryofShadows"
		"2414FC7A.Viber"
		"41038Axilesoft.ACGMediaPlayer"
		"46928bounde.EclipseManager"
		"64885BlueEdge.OneCalendar"
		"89006A2E.AutodeskSketchBook"
		"A278AB0D.DisneyMagicKingdoms"
		"A278AB0D.DragonManiaLegends"
		"A278AB0D.MarchofEmpires"
		"ActiproSoftwareLLC.562882FEEB491"
		"AD2F1837.GettingStartedwithWindows8"
		"AD2F1837.HPJumpStart"
		"AD2F1837.HPRegistration"
		"AdobeSystemsIncorporated.AdobePhotoshopExpress"
		"Amazon.com.Amazon"
		"C27EB4BA.DropboxOEM"
		"CAF9E577.Plex"
		"CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC"
		"D5EA27B7.Duolingo-LearnLanguagesforFree"
		"D52A8D61.FarmVille2CountryEscape"
		"DB6EA5DB.CyberLinkMediaSuiteEssentials"
		"DolbyLaboratories.DolbyAccess"
		"Drawboard.DrawboardPDF"
		"E046963F.LenovoCompanion"
		"Facebook.Facebook"
		"Fitbit.FitbitCoach"
		"flaregamesGmbH.RoyalRevolt2"
		"GAMELOFTSA.Asphalt8Airborne"
		"KeeperSecurityInc.Keeper"
		"king.com.BubbleWitch3Saga"
		"king.com.CandyCrushFriends"
		"king.com.CandyCrushSaga"
		"king.com.CandyCrushSodaSaga"
		"king.com.FarmHeroesSaga"
		"LenovoCorporation.LenovoID"
		"LenovoCorporation.LenovoSettings"
		"Nordcurrent.CookingFever"
		"PandoraMediaInc.29680B314EFC2"
		"PricelinePartnerNetwork.Booking.comBigsavingsonhot"
		"SpotifyAB.SpotifyMusic"
		"ThumbmunkeysLtd.PhototasticCollage"
		"WinZipComputing.WinZipUniversal"
		"XINGAG.XING"
	)

	write "`n ***** Now removing AppxPackage(s) ***** `n"

    foreach ($app in $apps) {
		write "`n $app `n"
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers | Out-Null
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -AllUsers | Out-Null
    }

	# Bloatware features
	# First round, WindowsCapability(s)
	# Found under Settings -> Apps -> Optional features
	$features_1 = @(
		"App.StepsRecorder*"
		"App.Support.QuickAssist*"
		"Browser.InternetExplorer*"
		"Hello.Face*"
		"MathRecognizer*"
		"Media.WindowsMediaPlayer*"
		"Microsoft.Windows.MSPaint*"
		"Microsoft.Windows.Notepad*"
		"Microsoft.Windows.PowerShell.ISE*"
		"Microsoft.Windows.WordPad*"
		"OneCoreUAP.OneSync*"
		"OpenSSH.Client*"
		"OpenSSH.Server*"
		"Print.Fax.Scan*"
		"Print.Management.Console*"
	)

	write "`n ***** Now removing WindowsCapability(s) ***** `n"

    foreach ($feature in $features_1) {
		write "`n $feature `n"
		Get-WindowsCapability -Online | Where-Object { $_.Name -like $feature } | Remove-WindowsCapability -Online | Out-Null
    }

	# Second round, WindowsOptionalFeature(s)
	# Found under Control Panel -> Programs and Features -> Turn Windows features on or off
	$features_2 = @(
		"FaxServicesClientPackage"
		"LegacyComponents"
		"MediaPlayback"
		"Microsoft-Windows-Subsystem-Linux"
		"MicrosoftWindowsPowerShellV2Root"
		"MSRDC-Infrastructure"
		"NetFx3"
		"NetFx4-AdvSrvs"
		"Printing-Foundation-Features"
		"Printing-Foundation-InternetPrinting-Client"
		"Printing-Foundation-LPDPrintService"
		"Printing-Foundation-LPRPortMonitor"
		"Printing-PrintToPDFServices-Features"
		"Printing-XPSServices-Features"
		"SMB1Protocol"
		"SMB1Protocol-Client"
		"SMB1Protocol-Deprecation"
		"SMB1Protocol-Server"
		"SmbDirect"
		"WCF-Services45"
		"WCF-TCP-PortSharing45"
		"WindowsMediaPlayer"
		"WorkFolders-Client"
	)

	write "`n ***** Now disabling WindowsOptionalFeature(s) ***** `n"

	foreach ($feature in $features_2) {
		write "`n $feature `n"
		Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
	}

	# Lastly bloatware app(s) or program(s) that can't be removed by normal means because Microsoft marked them as "non-removable"
	$paths = @(
		"C:\Windows\SystemApps\Microsoft.AsyncTextService_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.BioEnrollment_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy"
		"C:\Windows\SystemApps\microsoft.windows.narratorquickstart_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy"
		"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy"
		"C:\Windows\SystemApps\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy"
		"C:\Windows\SystemApps\NcsiUwpApp_8wekyb3d8bbwe"
		"C:\Windows\SystemApps\ParentalControls_cw5n1h2txyewy"
		"C:\Windows\SystemApps\Windows.CBSPreview_cw5n1h2txyewy"
		"C:\Program Files\Internet Explorer"
		"C:\Program Files (x86)\Internet Explorer"
	)

	write "`n ***** Now forcefully disabling other Microsoft app(s) or program(s) ***** `n"

    foreach ($path in $paths) {
		$pathmanip = Split-Path $path
		$pathstring = -join ((48..57) + (97..122) | Get-Random -Count 16 | % {[char]$_})
		$pathstring = "$pathmanip\$pathstring"

		If ((Test-Path "$path")) {
			If ("$path" -like "MicrosoftEdg*") {
				Get-Process | Where-Object { $_.Name -like "MicrosoftEdg*" } | Stop-Process | Out-Null
			}

			Rename-Item "$path" "$pathstring" | Out-Null

			write "`n $path -> $pathstring `n"
		}
    }
}

function SvcTweaks {
	$services = @(
		"AJRouter"
		"ALG"
		"AppReadiness"
		"AssignedAccessManagerSvc"
		"BcastDVRUserService"
		"BcastDVRUserService*"
		"BluetoothUserService"
		"BluetoothUserService*"
		"BTAGService"
		"BthA2dp"
		"BthAvctpSvc"
		"BthEnum"
		"BthHFEnum"
		"BthLEEnum"
		"BthMini"
		"BTHMODEM"
		"BTHPORT"
		"bthserv"
		"BTHUSB"
		"CDPSvc"
		"CDPUserSvc"
		"CDPUserSvc*"
		"DeviceAssociationBrokerSvc"
		"DeviceAssociationBrokerSvc*"
		"DeviceAssociationService"
		"DevQueryBroker"
		"DsSvc"
		"Eaphost"
		"embeddedmode"
		"EntAppSvc"
		"fdPHost"
		"FDResPub"
		"fhsvc"
		"HvHost"
		"icssvc"
		"IKEEXT"
		"iphlpsvc"
		"IpxlatCfgSvc"
		"KtmRm"
		"LanmanServer"
		"LanmanWorkstation"
		"lfsvc"
		"lltdsvc"
		"lmhosts"
		"LxpSvc"
		"Microsoft_Bluetooth_AvrcpTransport"
		"MixedRealityOpenXRSvc"
		"MSiSCSI"
		"NcbService"
		"Netlogon"
		"perceptionsimulation"
		"PolicyAgent"
		"PrintWorkflowUserSvc"
		"PrintWorkflowUserSvc*"
		"QWAVE"
		"RasAuto"
		"RasMan"
		"SCardSvr"
		"ScDeviceEnum"
		"SCPolicySvc"
		"seclogon"
		"SensorDataService"
		"SensorService"
		"SensrSvc"
		"SessionEnv"
		"SharedAccess"
		"SharedRealitySvc"
		"SNMPTRAP"
		"spectrum"
		"Spooler"
		"SSDPSRV"
		"SstpSvc"
		"stisvc"
		"TapiSrv"
		"TermService"
		"tzautoupdate"
		"UmRdpService"
		"upnphost"
		"VacSvc"
		"vmicguestinterface"
		"vmicheartbeat"
		"vmickvpexchange"
		"vmicrdv"
		"vmicshutdown"
		"vmictimesync"
		"vmicvmsession"
		"vmicvss"
		"WalletService"
		"WarpJITSvc"
		"wcncsvc"
		"WebClient"
		"WEPHOSTSVC"
		"WFDSConMgrSvc"
		"WiaRpc"
		"WpcMonSvc"
		"WPDBusEnum"
		"WwanSvc"
		"XblAuthManager"
		"XblGameSave"
		"XboxGipSvc"
		"XboxNetApiSvc"
	)

	# Some services found here aren't listed explicitly under services.msc
	# You may view those services in HKLM:\SYSTEM\CurrentControlSet\Services\ via regedit.exe
	write "`n ***** Now disabling preinstalled system service(s) ***** `n"

	foreach ($service in $services) {
		$servicename = Get-Service -Name "$service" | Select-Object -Property 'Name' | Format-List | Out-String
		$servicename = $servicename.Replace('Name : ','')
		$servicename = $servicename.Trim()

		write "`n $servicename `n"

		Stop-Service -Force "$servicename" | Out-Null
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$servicename" -Name "Start" -PropertyType DWord -Value 4 | Out-Null
	}
}

function MiscTweaks {
	write "`n ***** Now applying MiscTweak(s) ***** `n"

	# Disable Accessibility Key Prompts (Sticky keys, Toggle keys, Filter keys)
	write "`n Disabling Accessibility Key Prompts `n"

	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "506" | Out-Null
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -PropertyType String -Value "58" | Out-Null
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -PropertyType String -Value "122" | Out-Null

	# Disable Autoplay
	write "`n Disabling Autoplay `n"

	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -PropertyType DWord -Value 1 | Out-Null

	# Disable Autorun
	write "`n Disabling Autorun `n"

	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 | Out-Null

	# Disable Hibernation Feature
	write "`n Disabling Hibernation Feature `n"

	New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -PropertyType DWord -Value 0 | Out-Null
	powercfg /HIBERNATE OFF | Out-Null

	# Disable SharingWizard
	write "`n Disabling SharingWizard `n"

	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -PropertyType DWord -Value 0 | Out-Null

	# Disable Sleep Feature
	write "`n Disabling Sleep Feature `n"

	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 | Out-Null
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0 | Out-Null
	powercfg /X monitor-timeout-ac 0 | Out-Null
	powercfg /X monitor-timeout-dc 0 | Out-Null
	powercfg /X standby-timeout-ac 0 | Out-Null
	powercfg /X standby-timeout-dc 0 | Out-Null

	# Disable System Restore Points
	write "`n Disabling System Restore Points `n"

	Disable-ComputerRestore -Drive "C:\" | Out-Null

	# Hide Hibernate and Sleep from flyout menu
	write "`n Hiding Hibernate and Sleep from flyout menu `n"

	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}

	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -PropertyType DWord -Value 0 | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -PropertyType DWord -Value 0 | Out-Null
}

function NetworkTweaks {
	write "`n ***** Now applying NetworkTweak(s) ***** `n"

	# Disable specific DNS settings on adapters
	write "`n Disabling specific DNS settings on adapters `n"

		# Append parent suffixes
		write "`n - Append parent suffixes `n"

		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 0 | Out-Null

		# Register this connections address in DNS
		write "`n - Register this connections address in DNS `n"

		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters" -Recurse -ErrorAction SilentlyContinue | Out-Null
		Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
			New-ItemProperty -Force -Path $_.PsPath -Name "RegistrationEnabled" -PropertyType DWord -Value 0 | Out-Null
		}

	# Disable Ipv6
	write "`n Disabling Ipv6 `n"

	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6" | Out-Null
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value "0xFFFFFFFF" | Out-Null

	# Disable LLDP
	write "`n Disabling LLDP `n"

	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp" | Out-Null

	# Disable LLTD
	write "`n Disabling LLTD `n"

	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio" | Out-Null
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr" | Out-Null

	# Disable MS Net Client
	write "`n Disabling MS Net Client `n"

	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient" | Out-Null

	# Disable NetBIOS
	write "`n Disabling NetBIOS `n"

	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
		New-ItemProperty -Force -Path $_.PsPath -Name "NetbiosOptions" -PropertyType DWord -Value 2 | Out-Null
	}
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -PropertyType DWord -Value 0 | Out-Null

	# Disable Power Management for adapters
	write "`n Disabling Power Management for adapters `n"

	foreach ($NIC in (Get-NetAdapter -Physical)){
		$PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | ? {$_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)}
		if ($PowerSaving.Enable){
			$PowerSaving.Enable = $false
			$PowerSaving | Set-CimInstance | Out-Null
		}
	}

	# Disable QoS
	write "`n Disabling QoS `n"

	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer" | Out-Null

	# Disable SMB Server
	write "`n Disabling SMB Server `n"

	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server" | Out-Null

	# Harden Windows Firewall
	write "`n Hardening Windows Firewall `n"

		# Remove all pre-existing firewall rules
		write "`n - Removing all pre-existing firewall rules `n"

		netsh advfirewall firewall delete rule name=all | Out-Null

		# Alter all firewall profiles to:
		# Block inbound & outbound unless specified
		# Disable notifications
		# Disable unicast responses
		# Disable all logging
		write "`n - Altering all firewall profiles `n"

		Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen False -AllowUnicastResponseToMulticast False -LogAllowed False -LogBlocked False -LogIgnored False | Out-Null

		# Set current network profile to public
		write "`n - Setting the current network profile to public `n"

		Set-NetConnectionProfile -NetworkCategory Public | Out-Null

		# Setup some basic firewall rules
		write "`n - Setting up some basic firewall rules `n"

		$offlineonly =  ""

		if ( $offlineonly ) {
			# Inbound
			netsh advfirewall firewall add rule name="Block All Networking" dir=in action=block profile=any enable=yes | Out-Null

			# Outbound
			netsh advfirewall firewall add rule name="Block All Networking" dir=out action=block profile=any enable=yes | Out-Null
		} else {
			# Inbound
			netsh advfirewall firewall add rule name="Block Domain and Private Networking" dir=in action=block profile=domain,private enable=yes | Out-Null
			netsh advfirewall firewall add rule name="Core Networking - DHCP" dir=in action=allow program="%SystemRoot%\system32\svchost.exe" protocol=UDP localport=68 remoteport=67 profile=public enable=yes | Out-Null

			# Outbound
			netsh advfirewall firewall add rule name="Block Domain and Private Networking" dir=out action=block profile=domain,private enable=yes | Out-Null
			netsh advfirewall firewall add rule name="Block Windows Update" dir=out action=block program="%SystemRoot%\system32\svchost.exe" protocol=TCP remoteport=80,443 profile=any enable=yes | Out-Null
			netsh advfirewall firewall add rule name="Core Networking - DNS" dir=out action=allow program="%SystemRoot%\system32\svchost.exe" protocol=UDP remoteport=53 profile=public enable=yes | Out-Null
			netsh advfirewall firewall add rule name="Core Networking - DHCP" dir=out action=allow program="%SystemRoot%\system32\svchost.exe" protocol=UDP localport=68 remoteport=67 profile=public enable=yes | Out-Null
		}
}

function UITweaks {
	write "`n ***** Now applying UITweak(s) ***** `n"

	# Enable Build # on desktop
	write "`n Enabling Build # on desktop `n"

	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -PropertyType DWord -Value 1 | Out-Null

	# Enable Control Panel
		# Icon On Desktop
		write "`n Enabling Control Panel Icon On Desktop `n"

		If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
			New-Item -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
		}

		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0 | Out-Null
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0 | Out-Null

		# Small Icons
		write "`n Enabling Control Panel Small Icons `n"

		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -PropertyType DWord -Value 1 | Out-Null
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -PropertyType DWord -Value 1 | Out-Null

	# Enable Taskbar
		# Combine When Full
		write "`n Enabling Taskbar Combine When Full `n"

		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -PropertyType DWord -Value 1 | Out-Null
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -PropertyType DWord -Value 1 | Out-Null

		# Small Icons
		write "`n Enabling Taskbar Small Icons `n"

		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -PropertyType DWord -Value 1 | Out-Null

		# Tray Icons
		write "`n Enabling Taskbar Tray Icons `n"

		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -PropertyType DWord -Value 1 | Out-Null
}

function Restart {
	Write-Output "`nPress any key to restart..."
	[Console]::ReadKey($true) | Out-Null

	Write-Output "Restarting..."
	Restart-Computer
}


RequireAdmin

#CreateLog "sys-cleanup-function.log" "SysCleanup"
SysCleanup
#StopLog

#CreateLog "svc-tweaks.log" "SvcTweaks"
SvcTweaks
#StopLog

#CreateLog "misc-tweaks-function.log" "MiscTweaks"
MiscTweaks
#StopLog

#CreateLog "network-tweaks-function.log" "NetworkTweaks"
NetworkTweaks
#StopLog

#CreateLog "ui-tweaks-function.log" "UITweaks"
UITweaks
#StopLog

Restart

