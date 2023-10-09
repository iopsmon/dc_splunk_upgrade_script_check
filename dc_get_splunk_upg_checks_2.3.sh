#!/bin/bash
#+-------------------------------------------------------------------------------+
#DESCRIPTION:Obtain Some OS level and Splunk Info Before upgrade - and option to backup Splunk config
#USE: Under the Splunk user account copy to ~/ chmod +x and run on SH/IDX/HF/CM/DEPLOYER/DEPLOYMENT/LM
#This script can be run on any Splunk type server - cfg results will be produced if applicable.
#DATE:12/01/2023
#AUTHOR:Deepak Chohan
#VERSION:2.2
#Creates folder and places the outputs/tar file into this location ~/SERVER_NAME_DATE_TIME
#Checks if user has >2GB space in ~/ if not script will not run - can be adjusted - due to size of tar backup
#Gets OS Kernel / IP / CPU/MEM /tmp folder Info
#Gets Splunk Ulimist CFG
#Gets Network Ports Open
#Gets Splunk Volumes Size
#Gets KVstore Size
#Gets Splunk TLS Certs Info / CFG (Depends if they are installed and role requires them)
#Gets Splunk outputs CFG
#Gets /opt/splunk/etc/ and tars config (optional)
#Gets Apps Deployed to SHC Members via Deployer
#Gets Apps Deployed to IDX Peers via CM
#Gets Indexes Retention
#Get Apps Deployed vis Deployment - UF/HF
#Gets List Of Indexes (Only in Indexers Or SH Members )
#Gets Btool Check Info
#Gets ERRORS from splunkd.log
#+-------------------------------------------------------------------------------+



#Export Splunk
export SPLUNK_HOME=/opt/splunk
export USR_BIN=/usr/bin
export PATH=$SPLUNK_HOME/bin:$USR_BIN:$PATH

MY_KVSTORE_PATH=/opt/splunk/var/lib/splunk/kvstore

#Splunk User Name - Not Admin account - unless you know it
#echo "Enter your username:"
#read username

#Splunk user password
#echo "Enter your Splunk user password:"
#read -s password


date=$(date +"%d-%m-%Y %H:%M:%S")

#get the hostname
hostname=$(hostname)

#This creates a folder in ~/ - it will contain /opt/splunk/etc backup and various files for analysis  
cfg_folder=$hostname$"_"$(date +"%d-%m-%Y_%H_%M_%S")
mkdir ~/$cfg_folder

# Get the available disk space
disk_space=$(df -h | grep '/$' | awk '{print $4}')

# Get the CPU usage
cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')

# Get the total and used memory
mem=$(free -m | awk 'NR==2{print $3"MB", $2"MB"}')

# Get the /tmp space
tmp_space=$(df -h / | awk '{print $4}' | tail -1 | tr -d 'G')


#Get Ulimits conf for Splunk
ulimits_cfg=$(cat /etc/security/limits.conf | grep splunk)

#Splunk Checks
# Get the current size of the /opt/splunk folder
splunk_size=$(du -sh /opt/splunk | awk '{print $1}')

#Get the current size of the /opt/splunk folder
splunk_etc_size=$(du -sh /opt/splunk/etc | awk '{print $1}')

#Get the current size of the KVStore folder
splunk_kvstore_size=$(du -sh /opt/splunk/var/lib/splunk/kvstore |  awk '{print $1}')

#Splunk status - version
splunk_status=$(sudo systemctl status Splunkd.service | grep Active  | awk '{print $2 $3 $4 $5 $6 $7 }')
splunk_version=$(splunk version)
#splunk_tcp_ssl_port=$(splunk btool inputs list --debug | grep splunktcp-ssl | awk '{print $2}')

#This outputs the indexer TLS port CFg
splunk_tcp_idx_ssl_port=$(splunk btool inputs list --debug | grep splunktcp-ssl | awk '{print $0}')

#This outputs the HTTP Web Port
splunk_tcp_web_port=$(splunk btool web list --debug | grep httpport | awk '{print $0}')

splunk_outputs=$(splunk btool outputs list --debug | grep server | awk -F "=" '{print $2}')
splunk_ssl_cert_verify_cfg=$(splunk btool server list --debug | grep "sslVerifyServerCert" | head -1 | awk '{print $2 $3 $4 }' )
splunk_ssl_hostname_verify_cfg=$(splunk btool server list --debug | grep "sslVerifyServerName" | head -1 | awk '{print $2 $3 $4 }' )

#Certs
splunk_server_cert_pem_cfg=$(splunk cmd btool inputs list --debug | grep serverCert | head -1 |  awk '{print $2 $3 $4}')
splunk_web_cert_pem_cfg=$(splunk cmd btool web list --debug | grep serverCert | awk '{print $2 $3 $4}')
splunk_server_cert_pem_file=$(splunk cmd btool inputs list --debug | grep serverCert | head -1 |  awk '{print $4}')
splunk_web_cert_pem_file=$(splunk cmd btool web list --debug | grep serverCert |  awk '{print $4}')
my_server_cert_path="$splunk_server_cert_pem_file"
my_web_cert_path=$(echo $splunk_web_cert_pem_file | sed 's|$SPLUNK_HOME|/opt/splunk|g')

#Other Key CFG
#Vol Info
splunk_vol_paths=$(for i in $(/opt/splunk/bin/splunk btool indexes list --debug | grep path | awk '{print $4}' | sed 's/$SPLUNK_DB//g');  do echo $i $(du -sh $i | awk '{print $1}');  done)
splunk_vol_cfg=$(/opt/splunk/bin/splunk btool indexes list --debug  | grep -e "path" -e "maxVolumeDataSizeMB" -e "\[volume:hot\]" -e "\[volume:cold\]" -e "\[volume:summary\]" -e "\[volume:frozen\]" | sed  's/.*\$SPLUNK_DB//')

#Index Info
splunk_indexes=$(/opt/splunk/bin/splunk btool indexes list --debug | grep homePath | grep volume  | awk '{print $4}' | cut -d '/' -f 2)
splunk_total_indexes=$(/opt/splunk/bin/splunk btool indexes list --debug | grep homePath | grep volume | awk '{print $4}' | cut -d '/' -f 2 | wc -l)
splunk_cfg_indexes=$(/opt/splunk/bin/splunk btool indexes list --debug | grep homePath | grep volume  | awk '{print $4}' | cut -d '/' -f 2)

#KV Store Info
splunk_kvstore=$(splunk btool server list --debug  | grep "storageEngine =" |  awk '{print $4}')

#web HTTP Web CFG status
splunk_web_http_cfg=$(find /opt/splunk/etc/apps/ -name "*.conf" -exec grep -v '#' {} + | grep -E "enableSplunkWebSSL" | awk -F: '{print $0}')

#Get the Master / manager URI
splunk_master_manager_uri_cfg="$(splunk btool server list --debug | grep -e "master_uri" -e "manager_uri")"


# Check if openssl is installed
if command -v openssl >/dev/null 2>&1; then
  echo -e "\033[1;32m openssl is installed \033[0m"
else
  echo -e "\033[31m openssl is not installed - some output will not be displayed\033[0m"
fi

# Check if netstat is installed
if command -v netstat >/dev/null 2>&1; then
  echo -e "\033[1;32m netstat is installed \033[0m"
else
  echo -e "\033[31m netstat is not installed - some output will not be displayed\033[0m"
fi

#Functions
#Function to check the flavour of Linux and kernel version


check_flavour_and_kernel() {
    # Get the name of the Linux distribution
    distro_name=$(cat /etc/os-release | grep -w "NAME" | cut -d '"' -f2)
    echo -e  "Distribution:\033[1;32m$distro_name\033[0m"
    if [[ $distro_name =~ "Fedora" ]]; then
        echo -e  "Flavour:\033[1;32mFedora\033[0m"
    elif [[ $distro_name =~ "CentOS" ]]; then
        echo -e  "Flavour:\033[1;32mCentOS\033[0m"
    elif [[ $distro_name =~ "Red Hat" ]]; then
        echo -e  "Flavour:\033[1;32m Red Hat\033[0m"
    else
        echo -e  "Flavour:\033[1;32mUnknown\033[0m"
    fi

    # Get the kernel version
    kernel=$(uname -r)
    echo -e "Kernel:\033[1;32m$kernel\033[0m"
}

#Cert Checks Function
cert_checks() {

if [ -e "$my_server_cert_path" ]; then
    srv_cn_name=$(/usr/bin/openssl x509 -noout -subject -in $my_server_cert_path)
    srv_cert_expiry_date=$(/usr/bin/openssl x509 -in $my_server_cert_path -noout -enddate  | awk '{print $0}')
    echo -e "Splunk Server Cert Found:\033[1;32m$my_server_cert_path\033[0m"
 else
 echo -e "No Server Cert Found - May not be required on this server "
fi


if [ -e "$my_web_cert_path" ]; then
    web_cn_name=$(/usr/bin/openssl x509 -noout -subject -in $my_web_cert_path)
    web_cert_expiry_date=$(/usr/bin/openssl x509 -in $my_web_cert_path -noout -enddate  | awk '{print $0}' )
   echo -e "Splunk Web Cert Found:\033[1;32m$my_web_cert_path\033[0m"
   else
  echo -e "No Web Cert Found - May not be required on this server"
 fi

echo -e "Splunk Server Cert CN Name Host:\033[1;32m$srv_cn_name\033[0m"
echo -e "Splunk Server Expiry Date:\033[1;32m$srv_cert_expiry_date\033[0m"
echo -e "Splunk Web Server Cert CN Name Host:\033[1;32m$web_cn_name\033[0m"
echo -e "Splunk Web Server Expiry Date:\033[1;32m$web_cert_expiry_date\033[0m"
}

#SSL Verify
check_sslverify_cfg_set() {
  if [ "$splunk_ssl_verify_cfg" == "sslVerifyServerName = false" ]; then
    echo "Variable is not set or is set to null"
    echo  $splunk_ssl_verify_cfg
  elif [ "$splunk_ssl_verify_cfg" = "sslVerifyServerName = true" ]; then
   echo "Variable is set to true"
  else
   echo "Variable is set, but not equal to true or null"
fi
}


# Check disk space in ~/ directory
splunk_backup_etc() {

free_space=$(df -h ~/ | awk '{print $4}' | tail -1 | tr -d 'G')
if (( $(echo "$free_space < 1" | bc -l) )); then
   echo -e "\033[31m Not enough disk space in ~/ directory - for backup you need more than 1GB  \033[0m"
   echo -e "Current Disk Space of ~/ directory is $free_space GB"
   exit 1
 else
  echo -e "Current Disk Space of ~/ directory is $free_space GB"
  echo "Do you want to create a backup of /opt/splunk/etc directory? (yes/no)"
  read -r answer

if [ "$answer" == "yes" ]; then
  # Create tar file of /opt/splunk/etc directory
  tar cfv splunk_config_$(date +%Y-%m-%d).tar /opt/splunk/etc
  # Copy tar file to ~/ directory
  mv ./splunk_config_$(date +%Y-%m-%d).tar ~/$cfg_folder
  echo "**********************************************************************************"
  echo "**********************************************************************************"
  echo -e "Splunk Backup:\033[1;32m Tar back up /opt/splunk/etc completed - see ~/ folder \033[0m"
   ls ~/
 else
   echo "**********************************************************************************"
   echo "**********************************************************************************"
   echo -e "\033[31mBackup not created for /opt/splunk/etc - You opted out \033[0m"
  fi
fi
}



# Check /tmp disk space in MB
check_tmp_space() {
  # Get the available disk space in MB for /tmp
  tmp_space=$(df -m /tmp | awk 'NR==2 {print $4}')
  
  # Define the threshold (5000MB)
  threshold=5000
  
  if [ "$tmp_space" -lt "$threshold" ]; then
    echo "Not enough disk space in /tmp directory - for application upgrades, you need more than 5000MB - increase space."
    echo "Current Disk Space of /tmp directory is $tmp_space MB."
    #exit 1
  else
    echo "Current Disk Space of /tmp directory is $tmp_space MB."
  fi
}


#check Open Ports
check_open_ports() {
ports=$(/usr/bin/netstat -tuln | grep -v -e "Local" -e "(only" | awk '{print $4}' | cut -d: -f2 | sort -n | uniq)
 echo "Open Ports:"
  for port in $ports
    do
     if [[ $port == "53" ]]; then
      name="DNS"
     elif [[ $port == "8443" ]]; then
      name="Splunk HTTPS Web"
     elif [[ $port == "22" ]]; then
      name="SSH"
      elif [[ $port == "25" ]]; then
      name="SMTP"
     elif [[ $port == "21" ]]; then
      name="FTP"
     elif [[ $port == "111" ]]; then
      name="Portmapper"
     elif [[ $port == "631" ]]; then
      name="Internet Printing Protocol"
     elif [[ $port == "8000" ]]; then
      name="HTTP Insecure Port"
     elif [[ $port == "8065" ]]; then
      name="Splunk AppServer Port"
     elif [[ $port == "8089" ]]; then
      name="Splunk Mgmt Port"
     elif [[ $port == "8088" ]]; then
     name="Splunk HEC Port - May Be Different On Site"
     elif [[ $port == "8191" ]]; then
      name="Splunk KV Store Port"
     elif [[ $port == "9001" ]]; then
      name="Splunk AppServer Port"
     elif [[ $port == "9002" ]]; then
      name="Splunk SH Member Replication Port - May Be Different On Site"
     elif [[ $port == "9997" ]]; then
      name="Splunk Indexer Port"
     elif [[ $port == "9996" ]]; then
      name="Splunk Indexer Port"
     elif [[ $port == "9998" ]]; then
      name="Splunk Indexer TLS Port"
     else
      name="Other"
  fi
  echo -e "\033[1;32m $port\033[0m (\033[1;32m$name\033[0m)"
 done
 echo -e "Ports will vary from different sites and config"
}

#Get only ERRROS from splunkd
get_splunkd_errors_log() {
 get_errors=$(grep -o '[0-9]\{2\}-[0-9]\{2\}-[0-9]\{4\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\.[0-9]\{3\} +[0-9]\{4\} ERROR.*' /opt/splunk/var/log/splunk/splunkd.log > ~/$cfg_folder/splunkd_ERROR.log)
  echo -e "\033[33m===ERROR Log===\033[0m"
  echo -e "Splunk ERROR Log:\033[1;32m Review the output file splunkd.ERROR.log\033[0m"
}

#Get Btool Check output
get_btool_check() {
 btool_checks=$(splunk btool check > ~/$cfg_folder/splunk_btool_check.log)
  echo -e "\033[33m===Btool Check Log===\033[0m"
  echo -e "Btool Check Log:\033[1;32m Review the output file splunk_btool_check.log \033[0m"
}



#Ip address
# Get a list of all IP addresses
get_ip_info() {
ips=$(ip addr show | grep 'inet ' | awk '{print $2}')
# Print the list of IP addresses
  echo "List of IP addresses:"
   for ip in $ips; do
    echo -e "IP Info:\033[1;32m$ip\033[0m\t Subnet Mask : $(ip addr show | grep $ip -A2 | grep 'inet ' | awk '{print $4}')"
  done
}

# Get the current list of installed local apps
get_apps_list() {
splunk_apps_dirs=("/opt/splunk/etc/apps" "/opt/splunk/etc/peer-apps" "/opt/splunk/etc/slave-apps")
for dir in "${splunk_apps_dirs[@]}"
  do
    if [ -d "$dir" ]; then
        # search for app.conf files in the directory and its subdirectories
        find "$dir" -name app.conf -exec grep -E "id =|version =|label = |state = " {} + > ~/$cfg_folder/splunk_app_list.txt
    fi
done
echo -e "\033[33m===Splunk Installed Apps===\033[0m"
echo -e "Splunk Installed Apps Check:\033[1;32m Review the list of installed apps splunk_app_list.txt\033[0m"
}

#Get the apps from the deployer that are for the SHC members
get_deployer_apps() {
splunk_deployer_apps_dirs=("/opt/splunk/etc/shcluster/apps")
for dir in "${splunk_deployer_apps_dirs[@]}"
  do
    if [ -d "$dir" ]; then
        # search for app.conf files in the directory and its subdirectories
        find "$dir" -name app.conf -exec grep -E "id =|version =|label = " {} + > ~/$cfg_folder/splunk_deployer_sh_app_list.txt
    fi
done


echo -e "\033[33m===Splunk Deployer SHC Installed Apps===\033[0m"
echo -e "Splunk SHC Deployer Apps Check:\033[1;32m Review the list of installed apps splunk_deployer_app_list.txt\033[0m"
}

#Gets the apps from the Cluster Master / Manager  that are for the indexers
get_cm_apps() {
splunk_cm_apps_dirs=("/opt/splunk/etc/master-apps" "/opt/splunk/etc/manager-apps")
for dir in "${splunk_cm_apps_dirs[@]}"
  do
    if [ -d "$dir" ]; then
        # search for app.conf files in the directory and its subdirectories
        find "$dir" -name app.conf -exec grep -E "id =|version =|label =|state = " {} + > ~/$cfg_folder/splunk_cm_idx_app_list.txt
    fi
done
echo -e "\033[33m===Splunk CM Installed Apps===\033[0m"
echo -e "Splunk CM IDX Apps Check:\033[1;32m Review the list of installed apps splunk_cm_idx_app_list.txt\033[0m"
}


#Get the apps that are in the deployment server
get_deployment_apps() {
splunk_dp_apps_dirs=("/opt/splunk/etc/deployment-apps")
for dir in "${splunk_dp_apps_dirs[@]}"
  do
    if [ -d "$dir" ]; then
        # search for app.conf files in the directory and its subdirectories
        find "$dir" -name app.conf -exec grep -E "id =|version =|label = " {} + > ~/$cfg_folder/splunk_deployment_app_list.txt
    fi
done
echo -e "\033[33m===Splunk Deployment Installed Apps===\033[0m"
echo -e "Splunk Deployment Apps Check:\033[1;32m Review the list of installed apps splunk_deployment_app_list.txt\033[0m"
}


# Get the current retention periods of indexes - works only on CM and Indexers
get_index_retention_list() {
splunk_index_cfg_dirs=("/opt/splunk/etc/master-apps" "/opt/splunk/etc/manager-apps" "/opt/splunk/etc/peer-apps" "/opt/splunk/etc/slave-apps")
for idxcfgdir in "${splunk_index_cfg_dirs[@]}"
  do
    if [ -d "$idxcfgdir" ]; then
        find $idxcfgdir -name indexes.conf -exec grep -E "frozenTimePeriodInSecs|maxTotalDataSizeMB|\[" {} + | grep -v '#' > ~/$cfg_folder/splunk_index_retention_list.txt
    fi
done

#AIO Server Only
aio_path=(/opt/splunk/etc/apps)
 if [ -d "$aio_path" ]; then
        find $aio_path -name indexes.conf -exec grep -E "frozenTimePeriodInSecs|maxTotalDataSizeMB|\[" {} + | grep local | grep -v '#' > ~/$cfg_folder/splunk_index_retention_list_aio.txt
    fi

echo -e "\033[33m===Splunk Index Retention List===\033[0m"
echo -e "Splunk Index Retention List Check:\033[1;32m Review the list of indexes splunk_index_retention_list.txt\033[0m"
}


#Get all system local config - place cfg into one report file for analysis
get_local_cfg () {
local_cfg_files=$(find /opt/splunk/etc/system/local -type f -name "*.conf" | sort -u)
echo "====================Local Splunk CFG========================" > ~/$cfg_folder/splunk_system_local_cfg.txt
for local_cfg in $local_cfg_files; do
  echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" >> ~/$cfg_folder/splunk_system_local_cfg.txt
  echo $local_cfg >> ~/$cfg_folder/splunk_system_local_cfg.txt
  echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" >> ~/$cfg_folder/splunk_system_local_cfg.txt
  cat  $local_cfg >> ~/$cfg_folder/splunk_system_local_cfg.txt
  echo "============================================================" >> ~/$cfg_folder/splunk_system_local_cfg.txt
done
echo -e "\033[33m===Splunk System Local Config ===\033[0m"
echo -e "Splunk System Local CFG:\033[1;32m Review the local system config in splunk_system_local_cfg.txt\033[0m"
}


# Print Results
echo "**********************************************************************************"
echo "**********************************************************************************"
echo "Running Backup of /opt/splunk/etc folder"
splunk_backup_etc
echo -e "\033[33m**********************************************************************************\033[0m"
echo -e "Server Host:\033[1;32m$hostname\033[0m"
echo -e "\033[33m===OS Info===\033[0m"
check_tmp_space
echo -e "Available /tmp space:\033[1;32m$tmp_space\033[0m"
check_flavour_and_kernel
echo -e "Available disk space:\033[1;32m$disk_space\033[0m"
echo -e "CPU Usage:\033[1;32m$cpu\033[0m, Memory Free & Total:\033[1;32m$mem\033[0m"
echo -e "\033[33m===Ulimts For Splunk User===\033[0m"
echo -e "Splunk Ulimits Cfg:\033[1;32m\n$ulimits_cfg\033[0m"
echo -e "\033[33m===OS open Ports Info===\033[0m"
check_open_ports
echo -e "\033[33m===OS IP Info===\033[0m"
get_ip_info
echo -e "\033[33m===Splunk App Folder Sizes===\033[0m"
echo -e "Splunk Application Folder Sizes:"
echo -e "Current size of Splunk /opt/splunk:\033[1;32m$splunk_size\033[0m"
echo -e "Current size of Splunk Config /opt/splunk/etc:\033[1;32m$splunk_etc_size\033[0m"
echo -e "Current size of KVStore /opt/splunk/var/lib/splunk/kvstore:\033[1;32m$splunk_kvstore_size\033[0m"
echo -e "\033[33m===Splunk Volumes Info===\033[0m"
echo -e "Splunk Index Data Current Usage Sizes:"
echo -e "\033[1;32m$splunk_vol_paths\033[0m"
echo -e "Splunk Volume Config Sizes:"
echo -e "\033[1;32m$splunk_vol_cfg\033[0m"
echo -e "\033[33m===Splunk Indexes===\033[0m"
echo -e "\033[1;32m\n"$splunk_indexes"\033[0m"
echo -e "Splunk Total Indexes:\033[1;32m\n"$splunk_total_indexes"\033[0m"
echo -e "\033[33m===Splunk And Config Info===\033[0m"
echo -e "Splunkd Status:\033[1;32m$splunk_status\033[0m"
echo -e "Splunk Version:\033[1;32m$splunk_version\033[0m"
echo -e "Splunk KV Store:\033[1;32m$splunk_kvstore\033[0m"
echo -e "Splunk TCP Indexer Receiver SSL Inputs Port:\033[1;32m$splunk_tcp_idx_ssl_port\033[0m"
echo -e "Splunk TCP Web Inputs Port:\033[1;32m$splunk_tcp_web_port\033[0m"
echo -e "Splunk HTTP Web Status:\033[1;32m\n$splunk_web_http_cfg\033[0m"
echo -e "Splunk Manager - Master - Licence URI Cfg:\033[1;32m\n$splunk_master_manager_uri_cfg\033[0m"
echo -e "Splunk Outputs:\033[1;32m$splunk_outputs\033[0m"
echo -e "\033[33m===Splunk TLS Certs Info===\033[0m"
echo -e "Splunk TLS Cert Verify:\033[1;32m$splunk_ssl_cert_verify_cfg\033[0m"
echo -e "Splunk TLS Hostname Verify:\033[1;32m$splunk_ssl_hostname_verify_cfg\033[0m"
echo -e "Splunk Server Cert Pem Cfg:\033[1;32m$splunk_server_cert_pem_cfg\033[0m"
echo -e "Splunk Web Cert Pem Cfg:\033[1;32m$splunk_web_cert_pem_cfg\033[0m"

#call functions
cert_checks
get_splunkd_errors_log
get_btool_check
get_apps_list
get_deployer_apps
get_cm_apps
get_deployment_apps
get_index_retention_list
get_local_cfg
echo -e "Date:\033[1;32m$date\033[0m "
echo "**********************************************************************************"
echo "**********************************************************************************"
sleep 1
##End Of Code
#By Deepak Chohan
