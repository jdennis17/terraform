## PROVIDERS

provider "aws" {
  #access_key = ""
  #secret_key = ""
  region = var.aws_region
}

## DATA

data "aws_vpc" "existing_vpc" {
  id = var.existing_vpc

}

data "aws_subnet" "existing_subnet" {
  id = var.existing_subnet

}


data "aws_iam_role" "existing_iam_role" {
  name = var.existing_iam_role

}

data "aws_security_group" "existing_sg_id" {
  id = var.existing_sg_id
}

data "aws_ssm_parameter" "db_password" {
  name = "/db/passwords/onestream-db"
  with_decryption = true  # required so the password is readable/useable when setting

}

data "aws_ssm_parameter" "ssl_password" {
  name = "/ssl/passwords/sslcert"
  with_decryption = true  # required so the password is readable/useable when setting

}

data "aws_ssm_parameter" "os_api_key" {
  name = "/key/passwords/os-apikey"
  with_decryption = true  # required so the password is readable/useable when setting

}


## RESOURCES

resource "aws_instance" "irit_os_vm" {
  ami                    = "ami-0db3480be03d8d01c" 
  instance_type          = var.instanceType
  key_name               = var.keyPair
  subnet_id              = var.existing_subnet
  vpc_security_group_ids = [var.existing_sg_id]
  iam_instance_profile   = var.existing_iam_role
  #security_groups = [var.existing_sg_id]
  get_password_data = "true"
  tags = {
    Name = var.instanceName
  }

  root_block_device {
    volume_size           = var.rootVolumeSize
    volume_type           = "gp2"
    delete_on_termination = true
    tags = {
      Name = "${var.instanceName}-OS-DISK"
    }
  }

  ebs_block_device {
    device_name           = "/dev/sdd" # D drive
    volume_size           = var.dataVolumeSize
    volume_type           = "gp3"
    delete_on_termination = true
    tags = {
      Name = "${var.instanceName}-DATA-DISK"
    }
  }
  user_data = <<-EOF
            <powershell>
          $timeZone = "Eastern Standard Time"  
          $start = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), $timeZone)
          $pemCert = @"
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
"@
            $certPath = "C:temprootCA.pem"
            # Save the PEM certificate to a file
            $pemCert | Out-File -FilePath $certPath -Encoding ascii

            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($certPath)

            $derCertPath = "C:temprootCA.der"
            [System.IO.File]::WriteAllBytes($derCertPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            # Install the root CA certificate using certutil
            certutil -addstore -f "Root" $derCertPath

            Remove-Item -Path $certPath
            Remove-Item -Path $derCertPath
            sleep 10
            cd C:\Users\Administrator\Downloads
            msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi /quiet
            sleep 60

            Add-Content -Path "C:\Program Files\Amazon\AWSCLIV2\awscli\botocore\cacert.pem" -Value @"
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
"@
            $disk = Get-Disk | Where-Object PartitionStyle -eq "RAW"
            if ($disk) {
                Initialize-Disk -Number $disk.Number -PartitionStyle GPT 
                New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -Confirm:$false
            }
            sleep 10

            & 'C:\Program Files\Amazon\AWSCLIV2\aws' sns publish --topic-arn "arn:aws:sns:us-east-1:654635185665:terraform-deployment" --subject 'Build Started' --message $start
            
            Set-TimeZone -Id "Eastern Standard Time"
            New-Item -ItemType Directory -Path "D:\Software"
            cd D:\Software
            & 'C:\Program Files\Amazon\AWSCLIV2\aws' s3 cp s3://jd-os-tf/ . --recursive
            & 'C:\Program Files\Amazon\AWSCLIV2\aws' s3 cp s3://mt-os-migration/8.5.1/ . --recursive
            & 'C:\Program Files\Amazon\AWSCLIV2\aws' s3 cp s3://mscftest/SQLServer2022-x64-ENU-Dev.iso SQLServer2022-x64-ENU-Dev.iso
            & 'C:\Program Files\Amazon\AWSCLIV2\aws' s3 cp s3://mscftest/SSMS-Setup-ENU.exe SSMS-Setup-ENU.exe
         Install-WindowsFeature -configurationfilepath D:\Software\DeploymentConfigTemplate.xml
            sleep 45
            
            New-Item -ItemType Directory -Path "D:\OneStream"
            New-Item -ItemType Directory -Path "D:\OneStream\Config"
            New-Item -ItemType Directory -Path "D:\OneStream\FileShare"
            New-Item -ItemType Directory -Path "D:\OneStream\SSO\Logs"
            sleep 5
            New-SmbShare -Name 'OneStream' -Path 'D:\OneStream'
            $folderPath = "D:\OneStream"
            $fileshare = "D:\OneStream\FileShare"
            $configPath = "D:\OneStream\Config"
            $account = "NT AUTHORITY\NETWORK SERVICE"

            $acl = Get-Acl $folderPath
            $arguments = $account, "ReadAndExecute", "ContainerInherit, ObjectInherit", "None", "Allow"
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $arguments
            $acl.SetAccessRule($accessRule)
            $acl | Set-Acl $folderPath

            $aclfs = Get-Acl $fileshare
            $argumentsfs = $account, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
            $accessRuleFs = New-Object System.Security.AccessControl.FileSystemAccessRule $argumentsfs
            $aclfs.SetAccessRule($accessRuleFs)
            $aclfs | Set-Acl $fileshare

            $aclConfig = Get-Acl $configPath
            $argumentsConfig = $account, "Write", "ContainerInherit, ObjectInherit", "None", "Allow"
            $accessRuleConfig = New-Object System.Security.AccessControl.FileSystemAccessRule $argumentsConfig
            $aclConfig.SetAccessRule($accessRuleConfig)
            $aclConfig | Set-Acl $configPath
            sleep 10
          
            # Install .NET Requirments
            Start-Process -Wait -FilePath "D:\Software\dotnet-hosting-8.0.14-win.exe" /q
            Start-Process -Wait -FilePath "D:\Software\windowsdesktop-runtime-8.0.14-win-x64.exe" /q
            sleep 20

            # Install OneStream Components
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - OneStream Install Start" | Out-File -FilePath "C:\Users\Administrator\Desktop\log.txt"
            Start-Process "msiexec.exe" -ArgumentList '/i "D:\Software\OneStreamServers-8.5.1.17017.msi" ADDLOCAL="ApplicationServer,WebServer,ServerConfigurationUtility,DatabaseConfigurationUtility" INSTALLDIR="D:\Program Files\OneStream Software\" /l*v "D:\OneStreamInstall.txt" /quiet' -wait
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - OneStream Install Stop" | Out-File -FilePath "C:\Users\Administrator\Desktop\log.txt" -append
            sleep 10
            
            # Install SQL Server
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SQL Server Install Start" | Out-File -FilePath "C:\Users\Administrator\Desktop\sql-log.txt" -append
            $isoPath = "D:\Software\SQLServer2022-x64-ENU-Dev.iso"
            Mount-DiskImage -ImagePath $isoPath
            $mountDrive = Get-Volume -FriendlyName "SQLServer2022" | Select-Object -First 1
            $installerPath = "$($mountDrive.DriveLetter):\setup.exe"
            Start-Process -FilePath $installerPath -ArgumentList '/q /ACTION=Install /FEATURES=SQL /INSTANCENAME=MSSQLSERVER /INSTALLSHAREDDIR="D:\Program Files\Microsoft SQL Server" /INSTALLSHAREDWOWDIR="D:\Program Files(x86)\Microsoft SQL Server" /INSTANCEDIR="D:\Program Files\Microsoft SQL Server" /SQLSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE" /SQLSYSADMINACCOUNTS="BUILTIN\Administrators" /AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE" /IACCEPTSQLSERVERLICENSETERMS /SECURITYMODE=SQL /SAPWD="P@ssw0rd2025!" /SQLSVCSTARTUPTYPE=Automatic /AGTSVCSTARTUPTYPE=Automatic' -Wait
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SQL Server Install Stop" | Out-File -FilePath "C:\Users\Administrator\Desktop\sql-log.txt" -append
         sleep 10
            Dismount-DiskImage -ImagePath $isoPath
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SSMS Install Start" | Out-File -FilePath "C:\Users\Administrator\Desktop\ssms-log.txt" -append
            Start-Process -FilePath "D:\Software\SSMS-Setup-ENU.exe" -ArgumentList "/quiet /Install" -wait
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SSMS Install Stop" | Out-File -FilePath "C:\Users\Administrator\Desktop\ssms-log.txt" -append

            Add-LocalGroupMember -Group "IIS_IUSRS" -Member "NT AUTHORITY\NETWORK SERVICE"
            Add-LocalGroupMember -Group "Performance Log Users" -Member "NT AUTHORITY\NETWORK SERVICE"
            Add-LocalGroupMember -Group "Performance Monitor Users" -Member "NT AUTHORITY\NETWORK SERVICE"

            New-NetFirewallRule -DisplayName 'SQL' -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('1433')
            New-NetFirewallRule -DisplayName 'OneStream' -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('50001', '50002')
   
         & 'C:\Program Files\Amazon\AWSCLIV2\aws' s3 cp s3://mt-os-migration/Blank-OS-DB/ . --recursive
                $RestoreCommand = @"
                USE master;
                RESTORE DATABASE OneStream_Framework FROM DISK = 'D:\Software\OneStream_Framework.bak'
                WITH REPLACE;
"@
            & 'D:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD' -Q $RestoreCommand
                $RestoreCommand = @"
                USE master;
                RESTORE DATABASE OneStream_IRIT FROM DISK = 'D:\Software\OneStream_App.bak'
                WITH REPLACE;
"@
            & 'D:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD' -Q $RestoreCommand    
            $dbpassword = "${data.aws_ssm_parameter.db_password.value}"
            $user = @"
             USE [master];
                CREATE LOGIN [onestream] WITH PASSWORD = '$dbpassword';
                ALTER LOGIN [onestream] WITH CHECK_EXPIRATION = OFF, CHECK_POLICY = OFF;
                EXEC sp_addsrvrolemember 'onestream', 'sysadmin';
"@
         & 'D:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\SQLCMD' -Q $user

            $certpassword = "${data.aws_ssm_parameter.ssl_password.value}"
            [System.Security.SecureString]$securePassword = ConvertTo-SecureString -String $certPassword -Force -AsPlainText
            Import-PfxCertificate -FilePath "D:\Software\RootCA.pfx" -CertStoreLocation "Cert:\LocalMachine\My" -Password $securePassword -Exportable

            $jsonContent = Get-Content -Raw -Path "D:\Program Files\OneStream Software\OneStreamWebRoot\OneStreamWeb\appsettings.json" | ConvertFrom-Json
            $jsonContent.StartupSettings.ConfigurationFolder = "D:\OneStream\Config"
            $jsonContent.StartupSettings.EnableHTTP = $true
            $jsonContent.StartupSettings.EnableHTTPS = $false
            $jsonContent | ConvertTo-Json | Set-Content -Path "D:\Program Files\OneStream Software\OneStreamWebRoot\OneStreamWeb\appsettings.json" -Force

            $jsonContent = Get-Content -Raw -Path "D:\Program Files\OneStream Software\OneStreamAppRoot\OneStreamApp\appsettings.json" | ConvertFrom-Json
            $jsonContent.StartupSettings.ConfigurationFolder = "D:\OneStream\Config"
            $jsonContent.StartupSettings.EnableHTTP = $true
            $jsonContent.StartupSettings.EnableHTTPS = $false
            $jsonContent | ConvertTo-Json | Set-Content -Path "D:\Program Files\OneStream Software\OneStreamAppRoot\OneStreamApp\appsettings.json" -Force

         $jsonContent = Get-Content -Raw -Path "D:\Program Files\OneStream Software\OneStreamWebApiRoot\OneStreamWebApi\appsettings.json" | ConvertFrom-Json
            $jsonContent.StartupSettings.ConfigurationFolder = "D:\OneStream\Config"
            $jsonContent.StartupSettings.EnableHTTP = $true
            $jsonContent.StartupSettings.EnableHTTPS = $false
            $jsonContent | ConvertTo-Json | Set-Content -Path "D:\Program Files\OneStream Software\OneStreamWebApiRoot\OneStreamWebApi\appsettings.json" -Force

            $jsonContent = Get-Content -Raw -Path "D:\Program Files\OneStream Software\OneStreamWebUIRoot\OneStreamWebUI\appsettings.json" | ConvertFrom-Json
            $jsonContent.XFWebServerStartupSettings.ConfigurationFolder = "D:\OneStream\Config"
            $jsonContent | ConvertTo-Json | Set-Content -Path "D:\Program Files\OneStream Software\OneStreamWebUIRoot\OneStreamWebUI\appsettings.json" -Force

            $jsonContent = Get-Content -Raw -Path "D:\Program Files\OneStream Software\OneStreamAppRoot\OneStreamMgmt\appsettings.json" | ConvertFrom-Json
            $jsonContent.StartupSettings.ConfigurationFolder = "D:\OneStream\Config"
            $jsonContent.StartupSettings.EnableHTTP = $true
            $jsonContent.StartupSettings.EnableHTTPS = $false
            $jsonContent | ConvertTo-Json | Set-Content -Path "D:\Program Files\OneStream Software\OneStreamAppRoot\OneStreamMgmt\appsettings.json" -Force

            $appConfigPath = "D:\Software\XFAppServerConfig.xml"
            $webConfigPath = "D:\Software\XFWebServerConfig.xml"            
            $destination = "D:\OneStream\Config"
            Copy-Item -Path $appConfigPath -Destination $destination
            Copy-Item -Path $webConfigPath -Destination $destination

            $xmlAppFilePath = "D:\OneStream\Config\XFAppServerConfig.xml"
            $xmlWebFilePath = "D:\OneStream\Config\XFWebServerConfig.xml"
            [xml]$xmlAppFile = Get-Content -Raw -Path $xmlAppFilePath
            [xml]$xmlWebFile = Get-Content -Raw -Path $xmlWebFilePath
            $xmlAppFile.OneStreamXF.AppServerConfigSettings.SecuritySettings.XFRestApiKey = "${data.aws_ssm_parameter.os_api_key.value}"
            $xmlAppFile.Save($xmlAppFilePath)
            $xmlWebFile.OneStreamXF.WebServerConfigSettings.SecuritySettings.XFRestApiKey = "${data.aws_ssm_parameter.os_api_key.value}"
            $xmlWebFile.Save($xmlWebFilePath)

            $appAppPool = "OneStreamAppAppPool"
            $webAppPool = "OneStreamWebAppPool"
            Import-Module -Name WebAdministration
            $appPool = Get-Item IIS:\AppPools\$appAppPool

            # Update app app pool identity - 2 is the value for the NetworkService built-in account
            $appPool.processModel.identityType = 2

            # Apply the changes
            $appPool | Set-Item
            $webPool = Get-Item IIS:\AppPools\$webAppPool
            # Update app app pool identity - 2 is the value for the NetworkService built-in account
            $webPool.processModel.identityType = 2

            # Apply the changes
            $webPool | Set-Item
            $cert = Get-ChildItem Cert:\LocalMachine\My | where { $_.Subject -like "*RootCA" }
            New-WebBinding -Name "OneStream Web Server Site" -Protocol ${var.protocol} -IPAddress ${var.ipAddress} -Port ${var.port} -HostHeader ${var.hostname}
            (Get-WebBinding -Name "OneStream Web Server Site" -Port ${var.port} -Protocol ${var.protocol}).AddSslCertificate("$($cert.thumbprint)", "my")

            iisreset
            
            # Send email notification about completion of deployment
            $timeZone = "Eastern Standard Time"
            $stop = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), $timeZone)
            & 'C:\Program Files\Amazon\AWSCLIV2\aws' sns publish --topic-arn "arn:aws:sns:us-east-1:654635185665:terraform-deployment" --subject 'Build Complete' --message $stop
            </powershell>
            EOF
}

### OUTPUTS ###

output "aws_instance_ip" {
  value = aws_instance.irit_os_vm.private_ip
  description = "The private IP of the EC2 instance"
  

}
