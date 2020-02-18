# -*- mode: ruby -*-
# vi: set ft=ruby :
#
#
#

# domain name
DOMAIN="boxes.test"
# netbios name of domain
NETBIOS="BOXES"
# dc of domain
DC="DC=boxes,DC=test"
# passwort that is used for SERVICE_ACC and TEST_ACC
PASSWORD="P@ssW0rD!"
# vm config of domain controller
DC_IMAGE="peru/windows-server-2019-datacenter-x64-eval"
DC_NAME="dc01"
DC_MEM=4096
DC_CPU=2
# service account that is used to bind to active directory
SERVICE_ACC="guac"
# test account that has access to configured remote hosts
TEST_ACC="testuser"
# ou used to put guacamole configs to
CONFIG_OU="configs"

# vm config of podman host
POD_IMAGE="centos/8"
POD_NAME="pod"
POD_MEM=1024
POD_CPU=1

# vm config of ubuntu host
UBU_IMAGE="generic/ubuntu1804"
UBU_NAME="ubu"
UBU_MEM=1024
UBU_CPU=1

# configure users session for libvirt
Vagrant.configure("2") do |config|
  config.vm.provider :libvirt do |libvirt|
    libvirt.qemu_use_session = true
    libvirt.uri = 'qemu:///session'
    libvirt.management_network_device = 'virbr0'
  end

  config.vm.define :dc01 do |dc01|
    dc01.vm.box = "#{DC_IMAGE}"
    dc01.vm.hostname = "#{DC_NAME}"
    dc01.vm.provider :libvirt do |libvirt|
      libvirt.memory = "#{DC_MEM}"
      libvirt.cpus = "#{DC_CPU}" 
    # https://github.com/rgl/windows-domain-controller-vagrant/blob/master/Vagrantfile
    # use the plaintext WinRM transport and force it to use basic authentication.
    # NB this is needed because the default negotiate transport stops working
    #    after the domain controller is installed.
    #    see https://groups.google.com/forum/#!topic/vagrant-up/sZantuCM0q4
    dc01.winrm.transport = :plaintext
    dc01.winrm.basic_auth_only = true
    end


    dc01.vm.provision "shell", reboot: true do |s|
    s.inline = <<-SHELL
      install-windowsfeature AD-Domain-Services,RSAT-AD-AdminCenter,RSAT-ADDS-Tools
      Import-Module ADDSDeployment
      $password = ConvertTo-SecureString "#{PASSWORD}" -AsPlainText -Force
      Install-ADDSForest \
        -CreateDnsDelegation:$false \
        -DatabasePath "C:\Windows\NTDS" \
        -DomainMode "7" \
        -DomainName "#{DOMAIN}" \
        -DomainNetbiosName "#{NETBIOS}" \
        -ForestMode "7" \
        -InstallDns:$true \
        -LogPath "C:\Windows\NTDS" \
        -NoRebootOnCompletion:$false \
        -SysvolPath "C:\Windows\SYSVOL" \
        -Force:$true \
        -SafeModeAdministratorPassword $password
      SHELL
    end
    

    dc01.vm.provision "shell" do |s|
    s.inline = <<-SHELL
      # https://github.com/rgl/windows-domain-controller-vagrant/blob/master/provision/domain-controller-configure.ps1
      # wait until we can access the AD. this is needed to prevent errors like:
      #   Unable to find a default server with Active Directory Web Services running.
      while ($true) {
        try {
            Get-ADDomain | Out-Null
            break
        } catch {
            Start-Sleep -Seconds 10
        }
      }

      $password = ConvertTo-SecureString "#{PASSWORD}" -AsPlainText -Force
      New-ADUser -Name "#{TEST_ACC}" -AccountPassword $password -Enabled $true
      New-ADUser -Name "#{SERVICE_ACC}" -AccountPassword $password -Enabled $true

      New-ADOrganizationalUnit -Name "#{CONFIG_OU}"
      SHELL
    end


    # add guacamole schema
    dc01.vm.provision "shell" do |s|
    s.inline = <<-SHELL
Add-Content -path c:/guacSchema.ldif @"
#Attribute definitions

dn: CN=guacConfigParameter,CN=Schema,CN=Configuration,#{DC}
changetype: ntdsschemaadd
objectClass: top
objectClass: attributeSchema
cn: guacConfigParameter
attributeID: 1.3.6.1.4.1.38971.1.1.2
attributeSyntax: 2.5.5.12
isSingleValued: FALSE
adminDisplayName: guacConfigParameter
adminDescription: guacConfigParameter
oMSyntax: 64
searchFlags: 1
lDAPDisplayName: guacConfigParameter
systemOnly: FALSE

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-

dn: CN=guacConfigProtocol,CN=Schema,CN=Configuration,#{DC}
changetype: ntdsschemaadd
objectClass: top
objectClass: attributeSchema
cn: guacConfigProtocol
attributeID: 1.3.6.1.4.1.38971.1.1.1
attributeSyntax: 2.5.5.12
isSingleValued: FALSE
adminDisplayName: guacConfigProtocol
adminDescription: guacConfigProtocol
oMSyntax: 64
searchFlags: 1
lDAPDisplayName: guacConfigProtocol
systemOnly: FALSE

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-

# Classes

dn: CN=guacConfigGroup,CN=Schema,CN=Configuration,#{DC}
changetype: ntdsschemaadd
objectClass: top
objectClass: classSchema
cn: guacConfigGroup
governsID: 1.3.6.1.4.1.38971.1.2.1
rDNAttID: cn
adminDisplayName: guacConfigGroup
adminDescription: guacConfigGroup
objectClassCategory: 1
lDAPDisplayName: guacConfigGroup
name: guacConfigGroup
systemOnly: FALSE
subClassOf: groupOfNames
mayContain: guacConfigParameter
mustContain: guacConfigProtocol

dn:
changetype: modify
add: schemaUpdateNow
schemaUpdateNow: 1
-
"@
ldifde -i -f c:/guacSchema.ldif -b administrator #{DOMAIN} vagrant -k -j . -c "CN=Schema,CN=Configuration,#{DC}" "#schemaNamingContext"
SHELL
    end

    # add guacamole dummy entry 
    dc01.vm.provision "shell" do |s|
    s.inline = <<-SHELL
    # dot after {POD_NAME} is required, because of an entry in /etc/hosts with the name of host-system that runs podman 
$hosts = @( "#{DC_NAME}", "#{POD_NAME}.", "#{UBU_NAME}" )
foreach ($hostname in $hosts) {
write-host "host: $hostname"
Add-Content -path c:/entry$hostname.ldif @"
DN: CN=$hostname,OU=#{CONFIG_OU},#{DC}
changetype: add
CN: $hostname
objectClass: guacConfigGroup
guacConfigProtocol: rdp
guacConfigParameter: hostname=$hostname
guacConfigParameter: port=3389
guacConfigParameter: ignore-cert=true
guacConfigParameter: resize-method=display-update
guacConfigParameter: enable-drive=true
guacConfigParameter: drive-name=Guacamole
guacConfigParameter: drive-path=/tmp/${GUAC_USERNAME}
guacConfigParameter: create-drive-path=true
guacConfigParameter: username=vagrant
guacConfigParameter: password=vagrant
member: CN=#{TEST_ACC},CN=Users,#{DC}
"@

ldifde -i -f c:/entry$hostname.ldif
}
SHELL
    end
  end
  # centos podman host and testhost 
  config.vm.define :pod do |pod|
    pod.vm.box = "#{POD_IMAGE}"
    pod.vm.hostname = "#{POD_NAME}"
    pod.vm.provider :libvirt do |libvirt|
      libvirt.memory = "#{POD_MEM}"
      libvirt.cpus = "#{POD_CPU}"
    end

    pod.vm.provision "shell" do |s|
      s.inline = <<-SHELL
        dnf -y update
        dnf -y install podman
        dnf -y install epel-release
        dnf -y install xrdp xorgxrdp

        systemctl enable xrdp
        systemctl start xrdp

        dnf -y install xfdesktop xfce4-session gnome-terminal
        echo xfce4-session > /etc/sysconfig/desktop
        
        podman run -dt --rm --name guacamole --pod new:guac \
              -v /etc/pki/ca-trust/extracted/java:/etc/ssl/certs/java \
              -e LDAP_HOSTNAME=#{DC_NAME} \
              -e LDAP_PORT=389 \
              -e LDAP_ENCRYPTION_METHOD=none \
              -e LDAP_SEARCH_BIND_DN="cn=#{SERVICE_ACC},cn=users,#{DC}" \
              -e LDAP_SEARCH_BIND_PASSWORD="#{PASSWORD}" \
              -e LDAP_USERNAME_ATTRIBUTE="samaccountname" \
              -e LDAP_USER_BASE_DN="cn=users,#{DC}" \
              -e LDAP_GROUP_BASE_DN="ou=groups,#{DC}" \
              -e LDAP_CONFIG_BASE_DN="ou=configs,#{DC}" \
              -e GUACD_HOSTNAME="localhost" \
              -p 8080:8080 guacamole/guacamole
        
        podman run -dt --rm --name guacd --pod guac guacamole/guacd
    	SHELL
      end
  end

  # Ubuntu test host
  config.vm.define :ubu do |ubu| 
    ubu.vm.box = "#{UBU_IMAGE}" 
    ubu.vm.hostname = "#{UBU_NAME}" 
    ubu.vm.provider :libvirt do |libvirt| 
      libvirt.memory = "#{UBU_MEM}"
      libvirt.cpus = "#{UBU_CPU}" 
    end 
    ubu.vm.provision "shell" do |s|
      s.inline = <<-SHELL
        apt -y update
        apt -y install xrdp xorgxrdp openbox
        SHELL
      end
  end  
end
