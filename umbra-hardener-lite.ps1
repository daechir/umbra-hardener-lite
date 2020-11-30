# ---------------------------------------------------------------------------------------------------------------------
#
#
# Author: Daechir
# Author URL: https://github.com/daechir
# Modified Date: 11/25/20
# Version: v1a
#
#
# ---------------------------------------------------------------------------------------------------------------------
#
#
# Changelog:
#		v1a
#			* Add additional bloatware.
#			* Add MiscTweaks function.
#			* Cleanup UITweaks function.
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
		"microsoft.windowscommunicationsapps"
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

	write "`n ***** Now removing Appx*Package ***** `n"

    foreach ($app in $apps) {
		write "`n $app `n"
        Get-AppxPackage -AllUsers -Name $app| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
    }

	# Bloatware features
	# First round, optional WindowsCapability features
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

	write "`n ***** Now removing WindowsCapability features ***** `n"

    foreach ($feature in $features_1) {
		write "`n $feature `n"
		Get-WindowsCapability -Online | Where-Object { $_.Name -like $feature } | Remove-WindowsCapability -Online | Out-Null
    }

	# Second round, optional WindowsFeature
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

	write "`n ***** Now disabling WindowsOptionalFeature ***** `n"

	foreach ($feature in $features_2) {
		write "`n $feature `n"
		Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -WarningAction SilentlyContinue | Out-Null
	}

	# Lastly bloatware apps or programs that can't be removed by normal means because Microsoft marked them as "non-removable"
	# First round, C:\Windows\SystemApps\
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
	)

    foreach ($path in $paths) {
		$FirstString = -join ((48..57) + (97..122) | Get-Random -Count 16 | % {[char]$_})

		If ((Test-Path "$path")) {
			If ("$path" -like "MicrosoftEdg*") {
				Get-Process | Where-Object { $_.Name -like "MicrosoftEdg*" } | Stop-Process
			}

			Rename-Item "$path" "C:\Windows\SystemApps\$FirstString"
		}
    }

	# Second round, user specified
	$SecondString = -join ((48..57) + (97..122) | Get-Random -Count 16 | % {[char]$_})

	# Disable Internet Explorer
	If ((Test-Path "C:\Program Files\Internet Explorer")) {
		Rename-Item "C:\Program Files\Internet Explorer" "C:\Program Files\$SecondString"
	}
	If ((Test-Path "C:\Program Files (x86)\Internet Explorer")) {
		Rename-Item "C:\Program Files (x86)\Internet Explorer" "C:\Program Files (x86)\$SecondString"
	}
}

function MiscTweaks {
	# Disable Accessibility Key Prompts (Sticky keys, Toggle keys, Filter keys)
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -PropertyType String -Value "506"
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -PropertyType String -Value "58"
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -PropertyType String -Value "122"
	
	# Disable Autoplay
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -PropertyType DWord -Value 1
	
	# Disable Autorun
	New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255
	
	# Disable SharingWizard
	New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -PropertyType DWord -Value 0
}

function NetworkTweaks {
	# Disable DNS settings on adapters
		# Append parent suffixes
		New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "UseDomainNameDevolution" -PropertyType DWord -Value 0

		# Register this connections address in DNS
		Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters" -Recurse -ErrorAction SilentlyContinue
		Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" | ForEach-Object {
			New-ItemProperty -Force -Path $_.PsPath -Name "RegistrationEnabled" -PropertyType DWord -Value 0
		}

	# Disable Ipv6
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value "0xFFFFFFFF"

	# Disable LLDP
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"

	# Disable LLTD
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"

	# Disable MS Net Client
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"

	# Disable NetBIOS
	Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
		New-ItemProperty -Force -Path $_.PsPath -Name "NetbiosOptions" -PropertyType DWord -Value 2
	}
	New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -PropertyType DWord -Value 0

	# Disable Power Management Option on Adapters
	foreach ($NIC in (Get-NetAdapter -Physical)){
		$PowerSaving = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi | ? {$_.InstanceName -match [Regex]::Escape($NIC.PnPDeviceID)}
		if ($PowerSaving.Enable){
			$PowerSaving.Enable = $false
			$PowerSaving | Set-CimInstance
		}
	}

	# Disable QoS
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"

	# Disable SMB Server
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"

	# Harden Windows Firewall
		# Remove all pre-existing firewall rules
		netsh advfirewall firewall delete rule name=all

		# Change all firewall profiles to:
		# Block inbound & outbound unless specified
		# Disable notifications
		# Disable unicast responses
		# Disable all logging
		Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen False -AllowUnicastResponseToMulticast False -LogAllowed False -LogBlocked False -LogIgnored False

	# Set current network profile to public
	Set-NetConnectionProfile -NetworkCategory Public
}

function UITweaks {
	# Enable Build # on desktop
	New-ItemProperty -Force -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -PropertyType DWord -Value 1

	# Enable Control Panel
		# Icon On Desktop
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value 0

		# Small Icons
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -PropertyType DWord -Value 1

	# Enable Taskbar 
		# Combine When Full
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -PropertyType DWord -Value 1
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -PropertyType DWord -Value 1
		
		# Small Icons
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -PropertyType DWord -Value 1
		
		# Tray Icons
		New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -PropertyType DWord -Value 1
}

function Restart {
	Write-Output "`nPress any key to restart..."
	[Console]::ReadKey($true) | Out-Null

	Write-Output "Restarting..."
	Restart-Computer
}


RequireAdmin

CreateLog "sys-cleanup-function.log" "SysCleanup"
SysCleanup
StopLog

CreateLog "misc-tweaks-function.log" "MiscTweaks"
MiscTweaks
StopLog

CreateLog "network-tweaks-function.log" "NetworkTweaks"
NetworkTweaks
StopLog

CreateLog "ui-tweaks-function.log" "UITweaks"
UITweaks
StopLog

Restart

