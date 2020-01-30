#ps1_sysnative

if (!(Test-Path setup_done)) {
$domainprefix = "domain_netbios_name"
$domain = "domain_name"
$computer = "$env:computername"
$password = "admin_password" | ConvertTo-SecureString -asPlainText -Force
$username = "$domainprefix\administrator"
$credential = New-Object System.Management.Automation.PSCredential -ArgumentList($username,$password)
net user /add administrator $password /y
net localgroup administrators /add administrator
net user guest /active:yes
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11"
Invoke-WebRequest -Uri 'https://github.com/ytisf/theZoo/raw/master/malwares/Binaries/Ransomware.Jigsaw/Ransomware.Jigsaw.zip' -Outfile 'c:\jigsaw.zip'
Invoke-WebRequest -Uri 'https://github.com/ytisf/theZoo/raw/master/malwares/Binaries/Ransomware.Cerber/Ransomware.Cerber.zip' -Outfile 'c:\cerber.zip'
Invoke-WebRequest -Uri 'https://github.com/ytisf/theZoo/raw/master/malwares/Binaries/Win32.KeyPass/Win32.KeyPass.zip' -Outfile 'c:\keypass.zip'
Invoke-WebRequest -Uri 'https://packages.wazuh.com/3.x/windows/wazuh-agent-3.9.5-1.msi' -Outfile 'c:\wazuh.msi'
start-process c:\wazuh.msi -ArgumentList 'ADDRESS="so_master_address" AUTHD_SERVER="so_master_address" /passive' -wait
## install python3
Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.7.0/python-3.7.0.exe' -Outfile 'c:\python-3.7.0.exe'
cd c:\
.\python-3.7.0.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
## install requests library with pip
cd 'c:\Program Files (x86)/Python37-32/Scripts'
pip install requests
## download python script and config file
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/GA-CyberWorkforceAcademy/metaTest/master/TrafficGen/noisy.py' -Outfile 'c:\noisy.py'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/GA-CyberWorkforceAcademy/metaTest/master/TrafficGen/config.json' -Outfile 'c:\config.json'
## First boot of new DC takes awhile.. try until success for up to 10 minutes.
$break = $false
[int]$attempt = "0"
do {
  try {
    Add-Computer -ComputerName $computer -DomainName $domain -Credential $credential
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
New-Item -ItemType file setup_done
exit 1003
} Else {
## run traffic generator
cd c:\
.\noisy.py --config config.json  
exit 1002
}