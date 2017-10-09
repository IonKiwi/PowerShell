$services = get-service
foreach($service in $services) {
	if (!($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running -or
			$service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::StartPending -or
			$service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::ContinuePending)) {
		
		#ManagementObject mObject = new ManagementObject(new ManagementPath("Win32_Service.Name='"+this.ServiceName+"'"))
		#mObject["StartMode"]
		
		$startMode = (Get-WmiObject win32_service -filter "name='$($service.Name)'").StartMode
		if ($startMode -eq "Auto") {
			#determ delayed start
			$a = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
			$delayed = $a.GetValue("DelayedAutostart", 0);
			if ($delayed -eq 1) {
				Write-Host "(delayed) $($service.Name): $($service.DisplayName) is stopped"
			}
			else {
				Write-Host "$($service.Name): $($service.DisplayName) is stopped"
			}
			try {
				$service.Start()
			}
			catch {
				Write-Host $_.Exception.Message -foreground yellow
			}
		}
	}
}
