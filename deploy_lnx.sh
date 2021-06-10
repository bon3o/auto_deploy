#!/usr/bin/env bash
info=0
error=0
backuped=0
server=$(grep -E '^\s*ServerActive' /etc/zabbix/zabbix_agentd.conf | cut -d '=' -f2 | cut -d ':' -f1 | xargs)
ts=$(date +%s)
url=http://$server/files/
list_postfix=linux_list.md5
get_postfix=local_scripts_linux/
local_files=$(find /opt/zabbix/scripts/ -type f ! -path '*/deploy_backup/*' -exec md5sum "{}" + | sed 's/  \/opt\/zabbix\/scripts//' ) # Non whitespaced
if [[ ! "$local_files" =~ ^[0-9a-z]{32}[\/].* ]]; then
    if [[ ! "$local_files" =~ ^$ ]]; then
    zabbix_sender -z $server -s $1 -k 'DeployError' -o "$local_files - getting hash of local files faced a problem. The output didnt match regexp" > /dev/null; info=1
    echo 1
    exit 0
    fi
fi

remote_files=$(curl --max-time 5 -s $url$list_postfix | sed 's/  //') # Non whitespaced
if [[ ! "$remote_files" =~ ^[0-9a-z]{32}[\/].* ]]; then
    zabbix_sender -z $server -s $1 -k 'DeployError' -o "$remote_files - server response didnt match regexp" > /dev/null; info=1
    echo 1
    exit 0
fi

intersect=$(echo $local_files $remote_files | tr ' ' '\n' | sort | uniq -d)
to_update=$(echo $remote_files $intersect | tr ' ' '\n' | sort | uniq -u)
to_delete=$(echo $to_update $local_files | tr ' ' '\n' | sed 's/.\{33\}//' | sort | uniq -d)
local_exclude_intersect=$(echo $intersect $local_files | tr ' ' '\n' | sed 's/.\{33\}//' | sort | uniq -u)
to_inform=($(echo $to_delete $local_exclude_intersect | tr ' ' '\n' | sort | uniq -u))
for files in "${to_inform[@]}"; do
    if [[ $2 -eq 1 ]]; then
        rm /opt/zabbix/scripts/$files
    else
        zabbix_sender -z $server -s $1 -k 'DeployError' -o "File $files exists in the local script folder but not in repository" > /dev/null; info=1
    fi
done
to_update=($(echo $to_update |tr ' ' '\n' | sed 's/.\{33\}//'))
to_delete=($to_delete)

if [[ -n $to_delete ]]; then
    for files in "${to_delete[@]}"; do
        backup='/opt/zabbix/scripts/deploy_backup/'$files
        backupdir=$(dirname $backup)
        cp /opt/zabbix/scripts/$files{,.$ts.bak} && mkdir -p $backupdir && mv /opt/zabbix/scripts/$files"."$ts".bak" $backupdir && rm /opt/zabbix/scripts/"$files" && backuped=1
    done
else
    backuped=1
fi

if [[ $backuped -ne 1 ]]; then
    zabbix_sender -z $server -s $1 -k 'DeployError' -o "Error while making backup of old files due to wrong permissions or no empty space on disk. No changes are made." > /dev/null
    echo 1
    exit 0
fi

for files in "${to_update[@]}"; do
    response=$(curl --create-dirs -s -o /opt/zabbix/scripts/$files $url$get_postfix$files -w '%{http_code}')
    if [[ $response -ne 200 ]]; then
        rm /opt/zabbix/scripts/$files
        error=1
        break
    fi
    [ -f /opt/zabbix/scripts/$files ] && chmod +x /opt/zabbix/scripts/$files;
done

if [[ $2 -eq 1 ]];then
    find /opt/zabbix/scripts/ -type d -empty -delete
fi

if [[ $error -ne 0 ]]; then
    for files in "${to_delete[@]}"; do
        [ -f /opt/zabbix/scripts/deploy_backup/$files"."$ts".bak" ] && touch /opt/zabbix/scripts/$files && rm /opt/zabbix/scripts/$files && cp /opt/zabbix/scripts/deploy_backup/$files"."$ts".bak" /opt/zabbix/scripts/$files
    done
    zabbix_sender -z $server -s $1 -k 'DeployError' -o "Error while trying to deploy new scripts. All changes were rolled back." > /dev/null
fi

if [[ $info -ne 1 ]]; then
    zabbix_sender -z $server -s $1 -k 'DeployError' -o 0 > /dev/null
fi

if [[ $error -ne 0 ]]; then
    echo 1
else
    echo 0
fi
