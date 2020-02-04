#ps1_sysnative
$ErrorActionPreference = 'Stop'

if (!(Test-Path domain_done)) {
$domainprefix = "domain_netbios_name"
$domain = "domain_name"
$password = "admin_password" | ConvertTo-SecureString -asPlainText -Force
$username = "$domainprefix\administrator"
$credential = New-Object System.Management.Automation.PSCredential -ArgumentList($username,$password)
## First boot of new DC takes awhile.. try until success for up to 10 minutes.
$break = $false
[int]$attempt = "0"
do {
  try {
    Add-Computer -DomainName $domain -Credential $credential
    New-Item -ItemType file domain_done
    $break = $true
  }
  catch {
    if ($attempt -gt 10){
      Write-Host "Could not join domain!"
      $break = $true
    }
    else {
      Write-Host "Join failed... retrying"
      Start-Sleep -Seconds 60
      $attempt = $attempt + 1
    }
  }
}
While ($break -eq $false)
}

net user /add administrator $password /y
net localgroup administrators /add administrator
net user guest /active:yes
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11"
Invoke-WebRequest -Uri 'https://github.com/ytisf/theZoo/raw/master/malwares/Binaries/Ransomware.Jigsaw/Ransomware.Jigsaw.zip' -Outfile 'c:\jigsaw.zip'
Invoke-WebRequest -Uri 'https://github.com/ytisf/theZoo/raw/master/malwares/Binaries/Ransomware.Cerber/Ransomware.Cerber.zip' -Outfile 'c:\cerber.zip'
Invoke-WebRequest -Uri 'https://github.com/ytisf/theZoo/raw/master/malwares/Binaries/Win32.KeyPass/Win32.KeyPass.zip' -Outfile 'c:\keypass.zip'
Invoke-WebRequest -Uri 'https://packages.wazuh.com/3.x/windows/wazuh-agent-3.9.5-1.msi' -Outfile 'c:\wazuh.msi'
start-process c:\wazuh.msi -ArgumentList 'ADDRESS="so_master_address" AUTHD_SERVER="so_master_address" /passive' -wait
exit 1001
