#!/usr/bin/env python
# -*- coding: utf-8 -*-
import bottle
import os
import sys
import argparse
import subprocess
import requests
import json
import zipfile
import io
import datetime
import tempfile
import shutil
import ConfigParser
from lxml import etree, objectify
from bottle import response, Response
import time
import logging
import socket
import re

config = ConfigParser.ConfigParser()
zurl = 'http://{0}/zabbix/api_jsonrpc.php'.format(socket.gethostname())
zheaders = {'Content-Type': 'application/json-rpc'}
lnx_external_dir = '/opt/zabbix/external'
lnx_alert_dir = '/opt/zabbix/alertscripts'
win_dir = '/opt/zabbix/deploy/local_scripts_windows'
lnx_rem_dir = '/opt/zabbix/deploy/local_scripts_linux'
backup_path = '/opt/zabbix/deploy/backup'
file_temp_path = '/tmp'
logging.basicConfig(level='INFO')

def generate_timestamp():
    now = str(datetime.datetime.now())[:19]
    timestamp = now.replace(':','-').replace(' ', '_')
    return timestamp

def generate_timestamp_for_description():
    today = datetime.datetime.today()
    timestamp = today.strftime("%d.%m.%Y %H:%M")
    return timestamp

def check_auth(zkey):
    type_id = 0
    alias = None
    data = {
        "jsonrpc": "2.0",
        "method": "user.checkAuthentication",
        "params": {
            "sessionid": zkey
            },
        "id": 1
    }
    try:
        user_data = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
    except:
        return 5, 'Error connecting to Zabbix API.'
    if not 'error' in user_data.keys():
        type_id = (user_data['result']['type'])
        alias = user_data['result']['alias']
        return 0, type_id, alias
    else:
        return 5, user_data['error']['data']

def check_host(zkey, host_name):
    zerror = 0
    exist = 1
    data = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "filter": {
                "host":host_name
                }
            },
        "auth": zkey,
        "id":1
    }
    r = requests.get(zurl, headers=zheaders, data=json.dumps(data))
    if r.status_code == 200:
        result = r.json()['result']
        if not result:
            exist = 0
            result = 0
    else:
        zerror = r.reason
    return exist, zerror, result

def get_host_by_id(zkey, host_id):
    data = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["host"],
            "hostids": host_id
            },
        "auth": zkey,
        "id": 1
    }
    r = requests.get(zurl, headers=zheaders, data=json.dumps(data)).json()
    hostName = r['result'][0]['host']
    return hostName

def check_template(zkey, template_name):
    zerror = 0
    exist = 1
    data = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {
            "output": "extend",
            "selectHosts": ["hostid"],
            "filter": {
                "host": template_name
                }
            },
        "auth": zkey,
        "id":1
    }
    r = requests.get(zurl, headers=zheaders, data=json.dumps(data))
    if r.status_code == 200:
        result = r.json()['result']
        if not result:
            exist = 0
            result = 0
    else:
        zerror = r.reason
    return exist, zerror, result

def get_groupIds_by_name(zkey, names):
    idsList = []
    data = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output": "groupids",
            "filter": {
                "name": names
            }
        },
        "auth": zkey,
        "id": 1
    }
    r = requests.get(zurl, headers=zheaders, data=json.dumps(data)).json()
    for result in r['result']:
        idsList.append(result.get('groupid'))
    return idsList

def get_ids_by_name(zkey, zType, names):
    idsList = []
    params = {}
    if zType == "host":
        params = {"output":["hostid"],"filter":{"host": names}}
    elif zType == "group":
        params = {"output":["hostid"],"groupids": names}
    elif zType == "groupNames":
        return get_ids_by_name(zkey, 'group', get_groupIds_by_name(zkey, names))
    data = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": params,
        "auth": zkey,
        "id": 1
    }
    r = requests.get(zurl, headers=zheaders, data=json.dumps(data)).json()
    for result in r['result']:
        idsList.append(result.get('hostid'))
    return idsList


def unlink(zkey, template_id, hosts):
    hostids = []
    for host in hosts:
        hostids.append(host['hostid'])
    template_id = [str(template_id)]
    data = {
        "jsonrpc": "2.0",
        "method": "template.massremove",
        "params": {
            "templateids": template_id,
            "hostids":hostids
            },
        "auth": zkey,
        "id":1
    }
    requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
    return 0

def link_to_hosts(zkey, template_id, hosts):
    data = {
        "jsonrpc": "2.0",
        "method": "template.massadd",
        "params": {
            "templates": [
                {
                    "templateid": template_id
                }
            ],
            "hosts":hosts
        },
        "auth": zkey,
        "id":1
    }
    r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
    return r

def add_comment_to_template(zkey, template_names, monName):
    time = generate_timestamp_for_description()
    for template in template_names:
        data = {
            "jsonrpc": "2.0",
            "method": "template.get",
            "params": {
                "output": [
                    "description",
                    "templateid"
                ],
                "filter": {
                    "host": [template]
                }
            },
            "auth": zkey,
            "id": 2
        }
        r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
        currentDescription = r['result'][0]['description'].encode('utf-8')
        templateId = r['result'][0]['templateid']
        newDescription = """----------\n {0} ZBX Auto-deploy:
Импортирован системой автоматического внедрения в рамках 
https://jira..ru/browse/{1}\n\n{2}""".format(time, monName, currentDescription)
        logging.info("""Adding comment: 
{}""".format(newDescription))
        data = {
            "jsonrpc": "2.0",
            "method": "template.update",
            "params": {
                "templateid": templateId,
                "description": newDescription
            },
            "auth": zkey,
            "id": 1
        }
        try:
            r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
        except:
            return 1
    return 0

def add_comment_to_host(zkey, host_names, monName):
    time = generate_timestamp_for_description()
    for host in host_names:
        data = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output": [
                    "description",
                     "hostid"
                ],
                "filter": {
                    "host": [host]
                    }
                },
            "auth": zkey,
            "id": 2
        }
        r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
        currentDescription = r['result'][0]['description'].encode('utf-8')
        hostId = r['result'][0]['hostid']
        newDescription = """----------\n {0} ZBX Auto-deploy:
Импортирован системой автоматического внедрения в рамках 
https://jira..ru/browse/{1}\n\n{2}""".format(time, monName, currentDescription)
        data = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {
                "hostid": hostId,
                "description": newDescription
            },
            "auth": zkey,
            "id":1
        }
        try:
            r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
        except:
            return 1
    return 0

def rename_template(zkey, template_id, template_name, template_visible_name, progress, hosts_id):
    timestamp = generate_timestamp()
    new_template_name = 'OLD_' + template_name + '_'  + timestamp
    linked_host_names = []
    if template_visible_name:
        new_template_visible_name = 'OLD_' + template_visible_name + '_'  + timestamp
        data = {
            "jsonrpc": "2.0",
            "method": "template.update",
            "params": {
                "templateid": template_id,
                "host": new_template_name,
                "name": new_template_visible_name
            },
            "auth": zkey,
            "id": 1
        }
    else:
        data = {
            "jsonrpc": "2.0",
            "method": "template.update",
            "params": {
                "templateid": template_id,
                "host": new_template_name
            },
            "auth": zkey,
            "id": 1
        }
    r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
    result = r['result']['templateids'][0]
    for host in hosts_id:
        linked_host_names.append(get_host_by_id(zkey, host['hostid']))
    progress['RenamingTemplate_' + template_name] = {'templateId' : template_id, 'templateOldName': template_name,
        'templateOldVisibleName': template_visible_name, 'templateBackupName' : new_template_name,
        'templateBackupVisibleName' : new_template_visible_name, "templateWasLinkedTo": linked_host_names}
    logging.info('Template {0} was linked to hosts: {1}'.format(template_name, linked_host_names))
    return result, progress

def rename_host(zkey, host_id, host_name, host_visible_name, progress):
    timestamp = generate_timestamp()
    new_host_name = 'OLD_' + host_name + '_'  + timestamp
    if host_visible_name:
        new_host_visible_name = 'OLD_' + host_visible_name + '_'  + timestamp
        data = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {
                "hostid": host_id,
                "host": new_host_name,
                "name": new_host_visible_name
            },
            "auth": zkey,
            "id": 1
        }
    else:
        data = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {
                "hostid": host_id,
                "host": new_host_name
            },
            "auth": zkey,
            "id": 1
        }
    r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
    result = r['result']['hostids'][0]
    progress['RenamingHost_' + host_name] = {'hostId' : host_id, 'hostOldName': host_name, 
        'hostOldVisibleName': host_visible_name, 'hostBackupName' : new_host_name, 
        'hostBackupVisibleName' : new_host_visible_name}
    return result, progress

def export_data(zkey, id, name, data_type, timestamp, progress):
    data = {
        "jsonrpc": "2.0",
        "method": "configuration.export",
        "params": {
            "options": {
                data_type: [
                    id
                ]
            },
        "format": "xml"
        },
        "auth": zkey,
        "id": 1
    }
    try:
        r = requests.get(zurl, headers=zheaders, data=json.dumps(data)).json()
        export_data = r['result']
        filename = ("{0}_{1}.xml.bak".format(name, timestamp))
        save_path = os.path.join(backup_path, filename)
        with io.open(save_path, 'w', encoding='utf8') as file:
            file.write(export_data)
        if data_type == 'templates':
            progress['exportingTemplate_' + name] = {'templateId' : id, 'templateName': name,
             'templateBackupName' : save_path}
        else:
            progress['exportingHost_' + name] = {'hostId' : id, 'hostName': name,
             'hostBackupName' : save_path}
    except:
        return 1
    return 0, progress

def make_executable(path):
    mode = os.stat(path).st_mode
    mode |= (mode & 0o444) >> 2    # copy R bits to X
    os.chmod(path, mode)

def move_files(movdir, dst, progress):
    error = 0
    local_progress = {}
    timestamp = generate_timestamp()
    for root, dirs, files in os.walk(movdir):
        subdir_created = 0
        file_existed = 0
        backup_name = ''
        new_path = ''
        backup_location =''
        for file in files:
            try:
                old_full_path = os.path.join(os.path.abspath(root), file)
                subfolder = os.path.split(old_full_path[(len(movdir)+1):])[0]
                if subfolder: #Check if files are in subfolder(s)
                    new_path = os.path.join(dst, subfolder) #New full path in destination with subfolder
                    if not os.path.exists(new_path):
                        os.makedirs(new_path)
                        if not os.path.exists(new_path):
                            deplerror = """Error while creating new subdirectory for file {0}. 
After creation commnad the path {1} was not found.""".format(file, new_path)
                            local_progress[file] = {'existed': file_existed, 
                                'backUpLocation': backup_location, 'subdirCreated': subdir_created, 
                                'subDirPath': new_path, 'delpoymentError': deplerror}
                            return [2, local_progress]
                        subdir_created = 1
                    dst_file = os.path.join(new_path, file)
                else:
                    dst_file = os.path.join(dst, file)
                if not os.path.exists(dst):
                    os.makedirs(dst)
                    if not os.path.exists(dst):
                        deplerror = """Error while creating new directory for file {0}.
After creation commnad the path {1} was not found.""".format(file, dst)
                        local_progress[file] = {'existed': file_existed, 'backUpLocation': backup_location,
                                                'subdirCreated': subdir_created, 'subDirPath': new_path, 
                                                'delpoymentError': deplerror}
                        return [2, local_progress]
                if not os.path.isfile(dst_file):  # folder exists, file does not
                        logging.info('Starting copy proccess: file {0} goes to {1}'.format(file, dst))
                        try:
                            shutil.copy(old_full_path, dst_file)
                        except:
                            logging.warning('No permissions to copy new file in folder {}!'.format(dst_file))
                        if not os.path.isfile(dst_file):
                            logging.warning('No file created wile copying from temporary location!')
                            deplerror = """Error while copying new file {0}. 
After copy commnad the path {1} was not found.""".format(file, dst_file)
                            local_progress[file] = {'existed': file_existed, 'backUpLocation': backup_location, 
                                'subdirCreated': subdir_created, 'subDirPath': new_path, 'delpoymentError': deplerror}
                            return [2, local_progress]
                        make_executable(dst_file)
                else:  # folder exists, file exists, backuping
                    backup_name = file + '_' + timestamp + '.bak'
                    backup_location = os.path.join(backup_path, backup_name)
                    if not os.path.exists(backup_path):
                        os.makedirs(backup_path)
                    shutil.move(dst_file, backup_location)
                    if os.path.isfile(dst_file):
                        deplerror = """Error while moving old file {0} to backup location {1}. 
After move commnad old file {0} still exists in repo.""".format(file, backup_location)
                        local_progress[file] = {'existed': file_existed, 'backUpLocation': backup_location, 
                            'subdirCreated': subdir_created, 'subDirPath': new_path, 'delpoymentError': deplerror}
                        return [2, local_progress]
                    shutil.copy(old_full_path, dst_file)
                    logging.info("""Starting copy proccess: file {0} goes to {1}. 
Old file existed and backuped to {2}""".format(file, dst, backup_location))
                    if not os.path.isfile(dst_file):
                        deplerror = """Error while copying new file {0} to repo. 
After copy command the file {0} does not exist in repo.""".format(dst_file)
                        local_progress[file] = {'existed': file_existed, 'backUpLocation': backup_location, 
                            'subdirCreated': subdir_created, 'subDirPath': new_path, 'delpoymentError': deplerror}
                        return [2, local_progress]
                    make_executable(dst_file)
                    file_existed = 1
                local_progress[file] = {'existed': file_existed, 'backUpLocation': backup_location, 
                                        'subdirCreated': subdir_created, 'subDirPath': new_path}
            except:
                error = 2
                local_progress[file] = {'existed': file_existed, 'backUpLocation': backup_location, 
                                        'subdirCreated': subdir_created, 'subDirPath': new_path}
        progress[movdir.split('/')[-1]] = local_progress
    return [error, progress]

def handle_archive(zkey, file_loaded, timestamp, monName):
        progress = {}
        first_phase = []
        second_phase = []
        error = 0
        hosts_id = None
        try:
            zf = zipfile.ZipFile(file_loaded)
        except:
            error = 1
            logging.error('Bad archive was loaded.')
            return error, 'Архив имеет неверный формат.'
        tempdir_name = (file_loaded + '_' + timestamp)
        tempdir = os.path.join('/tmp', tempdir_name)
        os.makedirs(tempdir)
        zf.extractall(tempdir)
        logging.info('Archive was unzipped to {0}.'.format(tempdir_name))
        move = move_files(tempdir + '/windows', win_dir, progress)
        progress = move[1]
        error = move[0]
        if error > 0:
            return [error, progress]
        move = move_files(tempdir + '/linux/remote', lnx_rem_dir, progress)
        progress = move[1]
        error = move[0]
        if error > 0:
            return [error, progress]
        move = move_files(tempdir + '/linux/external', lnx_external_dir, progress)
        progress = move[1]
        error = move[0]
        if error > 0:
            return [error, progress]
        move = move_files(tempdir + '/linux/alert', lnx_alert_dir, progress)
        progress = move[1]
        error = move[0]
        if error > 0:
            return [error, progress]

        deployConfigFile = '{}/deploy.conf'.format(tempdir)
        deployConfig = ConfigParser.ConfigParser()
        try:
            deployConfig.read(deployConfigFile)
            logging.info('Read config file {} succesfully.'.format(deployConfigFile))
        except:
            deployConfig = None
            logging.info('Failed to read config file {}.'.format(deployConfigFile))
        rest_files = list(file for file in os.listdir(tempdir) if os.path.isfile(os.path.join(tempdir, file)))
        for file in rest_files:
            extension = os.path.splitext(file)[1]
            if extension == '.xml':
                xml_file = os.path.join(tempdir, file)
                try:
                    tree = etree.parse(xml_file)
                    root = tree.getroot()
                except:
                    return 3, progress
                for element in root:
                    if element.tag == 'templates':
                        first_phase.append(xml_file)
                        break
                    elif element.tag == 'hosts':
                        second_phase.append(xml_file)
                        break
                logging.info('Completed parsing xml file {}.'.format(file))
        for file in first_phase:
            logging.info('Starting parsing template data in first phase.')
            linkedTemplates = {}
            hostsIdsToLink = {}
            templatesToDescript = []
            templatesToLink = []
            tree = etree.parse(file)
            root = tree.getroot()
            templates = root.findall('.//templates/template')
            for template in templates:
                hostsNamesToLink = []
                hostsIds = []
                hostsGroupsNamesToLink = []
                template_name = template.findtext('.//template')
                if template_name:
                    logging.info('Getting info for template {}'.format(template_name))
                    templatesToDescript.append(template_name)
                    if deployConfig.has_section(template_name):
                        logging.info('Template {} has a config file section.'.format(template_name))
                        hostsIdsToLink[template_name] = []
                        templatesToLink.append(template_name)
                        logging.info('Appending template {} to link list.'.format(template_name))
                        try:
                            hostsNamesToLink = deployConfig.get(template_name,'hosts').split(',')
                        except:
                            logging.info("""Template {} has no hosts key in 
config and will not be linked to any.""".format(template_name))
                        try:
                            hostsGroupsNamesToLink = deployConfig.get(template_name, 'groups').split(',')
                        except:
                            logging.info("""Template {} has no groups key in 
config and will not be linked to any.""".format(template_name))
                    if hostsNamesToLink:
                        logging.info("""Template {0} will be 
linked to hosts {1}.""".format(template_name, hostsNamesToLink))
                        for id in get_ids_by_name(zkey, "host", hostsNamesToLink):
                            hostsIds.append(id)
                    if hostsGroupsNamesToLink:
                        logging.info("""Template {0} will be linked to 
hosts in groups {1}.""".format(template_name, hostsGroupsNamesToLink))
                        for id in get_ids_by_name(zkey, "groupNames", hostsGroupsNamesToLink):
                            hostsIds.append(id)
                    hostsIdsToLink[template_name] = hostsIds
                    check = check_template(zkey, template_name)
                    if check[0]:
                        template_id = check[2][0]['templateid']
                        template_visible_name = check[2][0]['name']
                        hosts_id = check[2][0]['hosts']
                        template_saved = export_data(zkey, template_id, template_name, 
                            "templates", timestamp, progress)
                        if template_saved[0]:
                            logging.error("""Error exporting old template {0}.
No changes to templates are made.""".format(template_name))
                            progress['exportingTemplate_' + template_name] = {'templateId' : template_id, 
                                'templateName': template_name, 'templateVisibleName': template_visible_name, 
                                'templateError': 'Error exporting template', "templateWasLinkedTo": hosts_id}
                            error = 4
                            return error, progress
                        progress = template_saved[1]
                        #rename = rename_template(zkey, template_id, template_name, template_visible_name, progress, hosts_id)
                        #if rename[0] != template_id:
                        #    logging.error('Error renaming template {0}.'.format(template_name))
                        #    progress['RenamingTemplate_' + template_name] = {'templateId' : template_id, 
                        #       'templateName': template_name, 'templateVisibleName': template_visible_name, 
                        #       'templateError':rename[0], "templateWasLinkedTo": hosts_id}
                        #    error = 4
                        #    return error, progress
                        #progress = rename[1]
                        if hosts_id:
                            linkedTemplates[template_name] = hosts_id
                            logging.info("""Template with id {0} 
                            was linked to hosts with id {1}""".format(template_id, hosts_id))
                            #uninkTemplate = unlink(zkey, template_id, hosts_id)
            with open(file, 'r') as xml_file:
                xml = xml_file.read()
            data = {
                "jsonrpc": "2.0",
                "method": "configuration.import",
                "params": {
                    "format": "xml",
                    "rules" : {
                        "applications": {
                            "createMissing": True,
                            "deleteMissing": True
                            },
                        "discoveryRules": {
                            "createMissing": True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "graphs": {
                            "createMissing": True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "groups": {
                            "createMissing": True
                            },
                        "hosts": {
                            "createMissing": True,
                            "updateExisting": True
                            },
                        "httptests": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "images": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "items": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "maps": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "screens": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "templateLinkage": {
                            "createMissing":True
                            },
                        "templates": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "templateScreens": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "triggers": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "valueMaps": {
                            "createMissing":True,
                            "updateExisting": True
                            }
                        },
                    "source": xml
                },
                "auth": zkey,
                "id":1
            }
            try:
                logging.info('Starting import from file {0}'.format(file))
                r = requests.post(zurl, headers=zheaders, data=json.dumps(data)).json()
                logging.info("""Importing request from file {0} 
to Zabbix API succeded.""".format(file))
                if 'error' in r:
                    error = 5
                    logging.error('Error while importing template data. Zabbix API returned error.')
                    progress['ImportingTemplateFromFile_' + file] = r['error']
                    return [error, progress]
                logging.info('Adding comment to description of templates {0}.'.format(templatesToDescript))
                add_comment_to_template(zkey, templatesToDescript, monName)
                logging.info("""Import from file {0} 
made succesfully""".format(file))
                for template in templatesToLink:
                    check = check_template(zkey, template)
                    if check[0]:
                        templateId = check[2][0]['templateid']
                    else:
                        error = 5
                        progress['ImportingTemplateFromFile_' + file] = {"templateImportError" :
                            """After importing template from file, 
Z API returnd an error while trying to find the new template."""}
                        logging.error("""After importing template {0} from file, 
Z API returnd an error while trying to find the new template.""".format(template_name))
                        return [error, progress]
                    if hostsIdsToLink[template]:
                        result = link_to_hosts(zkey, templateId, hostsIdsToLink[template])
                        logging.info("""Linking template with id {0} to hosts with id {1}. 
Result : {2}""".format(templateId, hostsIdsToLink[template], result))
                    #if hosts_id:
                #    for template in linkedTemplates:
                #        template_name = template
                #        hosts_id = linkedTemplates[template_name]
                #        check = check_template(zkey, template_name)
                #        if check[0]:
                #            newTemplateId = check[2][0]['templateid']
                #            logging.info("""Linking template with id {0} to hosts 
                #               with id {1""".format(newTemplateId, hosts_id))
                #            linkTemplate = link(zkey, newTemplateId, hosts_id)
                #        else:
                #            error = 5
                #            progress['ImportingTemplateFromFile_' + file] = {"templateImportError" : 
                #               """After importing template from file, 
                #            Z API returnd an error while trying to find the new template."""}
                #            logging.error("""After importing template {0} from file, 
                #               Z API returnd an error while trying 
                #               to find the new template."""".format(template_name))
                #            return [error, progress]
            except:
                error = 5
                logging.error('While importing new templates Z API was unreachable.')
                return [error, progress]
            progress['ImportingTemplateFromFile_' + file] = r

        for file in second_phase:
            tree = etree.parse(file)
            root = tree.getroot()
            hostsToDescript = []
            hosts = root.findall('.//hosts/host')
            for host in hosts:
                host_name = host.findtext('.//host')
                check = check_host(zkey, host_name)
                hostsToDescript.append(host_name)
                if check[0]:
                    host_id = check[2][0]['hostid']
                    #host_visible_name = check[2][0]['name']
                    host_saved = export_data(zkey, host_id, host_name, 
                        'hosts', timestamp, progress)
                    if host_saved[0]:
                            logging.error("""Error exporting old host {0}. 
No changes to host are made.""".format(host_name))
                            progress['exportingHost_' + host_name] = {'hostId' : host_id, 
                                'hostName': host_name, 'hostError': 'Error exporting host'}
                            error = 6
                            return error, progress
                    progress = host_saved[1]
                    #rename = rename_host(zkey, host_id, host_name, host_visible_name, progress)
                    #if rename[0] != host_id:
                    #    progress['RenamingHost_' + host_name] = {'hostId' : host_id, 
                    #           'hostName': host_name, 'hostVisibleName': host_visible_name, 
                    #           'hostError':rename[0]}
                    #    error = 6
                    #    return [error, progress]
                    #progress = rename[1]
            with open(file, 'r') as xml_file:
                xml = xml_file.read()
            data = {
                "jsonrpc": "2.0",
                "method": "configuration.import",
                "params": {
                    "format": "xml",
                    "rules" : {
                        "applications": {
                            "createMissing": True,
                            "deleteMissing": True
                            },
                        "discoveryRules": {
                            "createMissing": True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "graphs": {
                            "createMissing": True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "groups": {
                            "createMissing": True
                            },
                        "hosts": {
                            "createMissing": True,
                            "updateExisting": True
                            },
                        "httptests": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "images": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "items": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "maps": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "screens": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "templateLinkage": {
                            "createMissing":True
                            },
                        "templates": {
                            "createMissing":True,
                            "updateExisting": True
                            },
                        "templateScreens": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "triggers": {
                            "createMissing":True,
                            "updateExisting": True,
                            "deleteMissing": True
                            },
                        "valueMaps": {
                            "createMissing":True,
                            "updateExisting": True
                            }
                        },
                    "source": xml
                },
                "auth": zkey,
                "id":1
            }
            try:
                r = requests.post(zurl, headers=zheaders, 
                                data=json.dumps(data)).json()
                add_comment_to_host(zkey, hostsToDescript, monName)
            except:
                error = 7
                return [error, progress]
            progress['ImportingHostFromFile_' + file] = r
        data = {'deployProgress': progress}
        return [error, json.dumps(data, indent=4)]

def operate(zkey, archive, uploadedFile):
    timestamp = generate_timestamp()
    new_logfile_name = 'deploy_' + timestamp + '.log'
    log_path = os.path.join(backup_path, 'deployment_logs')
    monName = uploadedFile.split('.zip')[0]
    if not os.path.exists(log_path):
        os.makedirs(log_path)
    with open(os.path.join(log_path, new_logfile_name), 'w') as log:
        result = handle_archive(zkey, archive, timestamp, monName)
        if result[0] == 1:
            return result[1]
        elif result[0] == 2:
            log.write(json.dumps(result[1]))
            return ("""Ошибка на этапе коприования новых файлов и резервирования старых. 
Подробности в логе: {}""".format(os.path.join(log_path, new_logfile_name)))
        elif result[0] == 3:
            log.write(json.dumps(result[1]))
            return ("""Ошибка на этапе парсинга xml файла из архива. 
Необходимо проверить лог на предмет внесенных 
изменений : {}""".format(os.path.join(log_path, new_logfile_name)))
        elif result[0] == 4:
            log.write(json.dumps(result[1]))
            return ("""Ошибка на этапе экспоритрования старого шаблона. 
Новый шаблон накачен не был. Необходимо проверить лог на предмет 
внесенных изменений : {}""".format(os.path.join(log_path, new_logfile_name)))
        elif result[0] == 5:
            log.write(json.dumps(result[1]))
            return ("""Ошибка на этапе импортирования нового шаблона. 
Необходимо проверить лог на предмет внесенных 
изменений : {}""".format(os.path.join(log_path, new_logfile_name)))
        elif result[0] == 6:
            log.write(json.dumps(result[1]))
            return ("""Ошибка на этапе экспоритрования старого узла сети. 
Необходимо проверить лог на предмет внесенных 
изменений : {}""".format(os.path.join(log_path, new_logfile_name)))
        elif result[0] == 7:
            log.write(json.dumps(result[1]))
            return ("""Ошибка на этапе импортирования нового узла сети. 
Необходимо проверить лог на предмет внесенных 
изменений : {}""".format(os.path.join(log_path, new_logfile_name)))
        log.write(result[1])
    return 0

@bottle.route('/deploy/upload/<key>', method='OPTIONS')
def lvambience(key):
    response.headers['Content-type'] = 'application/json'
    #response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST'
    response.headers['Access-Control-Allow-Headers'] = """Origin, 
    Accept, Content-Type, X-Requested-With, X-CSRF-Token"""
    return {}

@bottle.route('/deploy/upload/<key>', method='POST')
def up(key):
    #response.headers['Access-Control-Allow-Origin'] = '*'
    response.content_type = 'application/json'
    try:
        config.read('deploy.conf')
        zabbix_allowed_group = config.get('GROUP','group')
        zabbix_allowed_group = zabbix_allowed_group.split(';')
        zabbix_allowed_users = config.get('USERS','users')
        zabbix_allowed_users = zabbix_allowed_users.split(';')
    except:
        return 'Не найден конфигурационный файл deploy.conf'
    zuserType = check_auth(key)
    if zuserType[1] in zabbix_allowed_group and zuserType[2] in zabbix_allowed_users:
        logging.info('User {0} is starting deployment proccess'.format(zuserType[2]))
        upload = bottle.request.files.get('file')
        uploadedFile = upload.filename
        file_to_operate = os.path.join(file_temp_path, uploadedFile)
        try:
            upload.save(file_temp_path, overwrite=True)
            if not re.match(r'MON-\d{1,5}.zip', uploadedFile):
                logging.error("""File {} was successfully saved but 
name of file has incorrect formart. Should match pattern "MON-\d(1, 5).zip". 
No changes were made.""".format(uploadedFile))
                return """Имя загружаемого файла не соответствует необходимому формату. 
Развертывание произведено не было."""
            logging.info('File {} was successfully saved'.format(uploadedFile))
        except:
            logging.warning('File {} was not saved'.format(file_temp_path))
            return 'Невозможно сохранить архив во временной папке на сервере.'
        result = operate(key, file_to_operate, uploadedFile)
        if result == 0:
            return 'Развертывание пакета прошло успешно.'
    else:
        if zuserType[0] == 5:
            logging.warning("""Attempt to start deployment proccess 
but Zabbix session was terminated.""")
            return zuserType[1]
        else:
            logging.warning("""User {0} made attempt to start deployment proccess 
but he is not in allowed group.""".format(zuserType[2]))
            return 'Данному пользователю не разрешено совершать операции авто-деплоя.'
    return result

@bottle.route('/deploy/test')
def test():
    time = generate_timestamp_for_description()
    return Response('<h1>' + time + '</h1>')

if __name__ == '__main__':
    bottle.run(host='0.0.0.0', port=8080, debug=True)
    #main()


app = bottle.default_app()
