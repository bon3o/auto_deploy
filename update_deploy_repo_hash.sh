#!/usr/bin/env bash
error=0
find /opt/zabbix/deploy/local_scripts_linux -type f -exec md5sum {} + | sed 's/\/opt\/zabbix\/deploy\/local_scripts_linux//' > /opt/zabbix/deploy/temp_linux_list.md5 && mv /opt/zabbix/deploy/temp_linux_list.md5 /opt/zabbix/deploy/linux_list.md5 && error=$((error + 1))
find /opt/zabbix/deploy/local_scripts_windows/  -type f -exec md5sum "{}" + | sed 's/\/opt\/zabbix\/deploy\/local_scripts_windows//'  | tr '\/' '\\' > /opt/zabbix/deploy/temp_windows_list.md5 && mv /opt/zabbix/deploy/temp_windows_list.md5 /opt/zabbix/deploy/windows_list.md5 && error=$((error + 2))
if [[ $error -eq 3 ]]; then
    echo 0
else
    echo "Error while updating script hash"
fi
