#!/bin/bash

cat << "EOF"
-------------------------------------------------------------
    __    _                                    
   / /   (_)___  __  ___  __                   
  / /   / / __ \/ / / / |/_/                   
 / /___/ / / / / /_/ />  <                     
/_____/_/_/ /_____,_/_/|_|   ___ __            
            /   | __  ______/ (_) /_____  _____
           / /| |/ / / / __  / / __/ __ \/ ___/
          / ___ / /_/ / /_/ / / /_/ /_/ / /    
         /_/  |_\__,_/\__,_/_/\__/\____/_/     
                                                                        
©Copyright: Johto Robbie. ( @johto1989 | vnhackernews.com )
-------------------------------------------------------------
EOF

if (( $EUID != 0 )); then
    echo "This script must be run as root!"
    exit
fi

getSystemInfo(){
    echo '--------------------------------------------------' 
    echo 'LIST SYSTEM INFO' 
    echo '--------------------------------------------------' 

    echo '------------------OS Version--------------------------------'
    uname -a
    echo '------------------PCI Devices--------------------------------'
    lspci
    echo '------------------USB Controllers--------------------------------'
    lsusb
    echo '------------------Linux Hardware Components--------------------------------'
    echo '1.system'
    dmidecode -t system
    echo '2.memory'
    cat /proc/meminfo
    echo '3.processor'
    ps -eo pcpu,pid,user,args | sort -r -k1
    echo '------------------Process Listening on a Particular Port--------------------------------'
    netstat -tulpn
}

checkVersion() {
    ver=uname -r

    echo '--------------------------------------------------' 
    echo 'LIST ALL PACKAGES INSTALLED' 
    echo '--------------------------------------------------' 

    if rpm -q $1 &> /dev/null; then
        rpm -q kernel --last 
        rpm -qa --last 
    # elif [[ "$(lsb_release -is)" == *"Kali"* ]]; then
    elif [[ -f "/var/log/dpkg.log" ]]; then
        rpm -qa
        grep -i "install" /var/log/dpkg.log 
    elif [[ -f "/var/log/pacman.log" ]]; then
        awk '/\[ALPM\] installed/ ' /var/log/pacman.log
    else
        echo 'not found installed';
    fi
}

checkServices() {
    echo '--------------------------------------------------' 
    echo 'LIST ALL RUNNING SERVICES' 
    echo '--------------------------------------------------' 
    systemctl list-units --type=service 
}

checkBackup() {
    echo '--------------------------------------------------' 
    echo 'LIST BACKUP PARTITION' 
    echo '--------------------------------------------------' 

    df -h
}

checkLogSize(){
    echo '--------------------------------------------------' 
    echo 'CHECK LOG SIZE' 
    echo '--------------------------------------------------'

    grep -w "^\s*max_log_file\s*=" /etc/audit/auditd.conf
}

getUserUsingSSH(){
    echo '--------------------------------------------------' 
    echo 'LIST SSH USER' 
    echo '--------------------------------------------------'

    grep AllowUsers /etc/ssh/sshd_config
}

getCrontab(){
    echo '--------------------------------------------------' 
    echo 'LIST CRONTAB' 
    echo '--------------------------------------------------'

    crontab -l
}

getNetworkInfo(){
    echo '--------------------------------------------------' 
    echo 'LIST NETWORK INFOMATION' 
    echo '--------------------------------------------------'

    ifconfig
    ip addr
    netstat -i
}

if [ "$1" == "-h" ]; then
    echo "This script must be run with super-user privileges."
    echo "Usage: ./tachi.sh audit | tee output.txt"
    exit 0
elif [ "$1" == "audit" ]; then
    getSystemInfo
    echo ' '
    checkVersion
    echo ' '
    checkServices
    echo ' '
    checkBackup
    echo ' '
    checkLogSize
    echo ' '
    getUserUsingSSH
    echo ' '
    getCrontab
else
   echo "Try '-h' for more information" 
fi
