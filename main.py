import paramiko
import time
import multiprocessing
import re
# import ipaddress
# import subprocess
from datetime import datetime
# from easysnmp import snmp_walk, Session
import netsnmp

from settings import *

# Start time at work
start_time = datetime.now()


def check_ip(ipaddress):
    check_ipaddress = re.findall(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1"
                                 "[0-9]""{2}|2[0-4][""0-9]|25[0-5])$", ipaddress)
    if check_ipaddress:
        return ipaddress
    else:
        return None


# Get ip_full list from file
# def get_ip_list():
#     devices_ip_list = []
#     try:
#         with open('ip') as dev_ip:
#             for line in dev_ip.readlines():
#                 check_ip = re.findall(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1"
#                                       "[0-9]""{2}|2[0-4][""0-9]|25[0-5])$", line)
#                 if not check_ip:
#                     print(colors.FAIL + "Invalid IP - " + str(line) + colors.ENDC)
#                 else:
#                     devices_ip_list.append(line.replace('\n', ''))
#             dev_ip.close()
#     except IOError:
#         print('File do not open because ip_full file does not exist')
#     devices_ip_list = [line.replace('\n', '')
#                        for line in dev_ip.readlines()
#                        if check_ip(ipaddress=line) is not None]
#     return devices_ip_list

# Get ip list from file
def get_ip_list():
    try:
        return [line.replace('\n', '') for line in open('ip').readlines() if check_ip(ipaddress=line) is not None]
    except IOError:
        print('File do not open because ip_full file does not exist')


# SNMP connection to device for get_device_id
def snmp_connection(ip, community):
    time.sleep(1)
    oid = netsnmp.Varbind('.1.3.6.1.2.1.1.1')
    # print(oid, ip_full, community)  # Debug option
    snmp_res = netsnmp.snmpwalk(oid, Version=2, DestHost=ip, Community=community)
    return snmp_res


# Get device vendor from snmp
def get_device_id(ipaddress):
    vendor_id = None
    snmp_walk = ''
    if vendor_id is None:
        # print(f'analyze device {ipaddreess}')
        try:
            # snmp_walk = snmp_walk(oids='1.3.6.1.2.1.1.1', hostname=ipaddreess, community=community1, version=2)
            snmp_walk = snmp_connection(ipaddress, community1)
            if snmp_walk == ():
                snmp_walk = snmp_connection(ipaddress, community2)
        except Exception as snmp_error:
            print(f'{ipaddress}: snmp connections error ' + str(snmp_error))
        if re.search(r'\bCisco\b', str(snmp_walk)):
            vendor_id = 'Cisco'
        elif re.search(r'\bHuawei\b', str(snmp_walk)) or \
                re.search(r'\bHUAWEI\b', str(snmp_walk)):
            vendor_id = 'Hua'
        elif re.search(r'', str(snmp_walk)):
            vendor_id = None
    return vendor_id


# Function ssh connectivity and sensing device commands without multiprocessing
def ssh_connect(ipaddress):
    vendor = get_device_id(ipaddress)
    if vendor is not None:
        print(colors.BOLD + f"\nStart connection to: {ipaddress} ({vendor})" + colors.ENDC)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ipaddress, username=user, password=password, port=port, look_for_keys=False,
                           allow_agent=False, timeout=5)
        except (paramiko.AuthenticationException,
                paramiko.ssh_exception.NoValidConnectionsError, paramiko.SSHException) as connection_error:
            print(colors.FAIL + f"\nError connecting to {ipaddress}: {connection_error}" + colors.ENDC)
        try:
            with client.invoke_shell() as ssh_cli:
                if vendor == 'Cisco':
                    ssh_cli.send('terminal length 0\n'.encode())
                    time.sleep(0.5)
                    ssh_cli.send('sh run | i tacacs-server host\n'.encode())

                    # This timer needed for buffered result in "result"
                    time.sleep(3)

                    result = ssh_cli.recv(99999).decode('ascii')

                    if re.search(r'\b10.0.0.172\b', result):
                        time.sleep(0.5)
                        print(f'Tacacs server is old')
                        ssh_cli.send('conf t\n'.encode())
                        time.sleep(0.5)
                        ssh_cli.send('tacacs-server host 10.0.3.14\n'.encode())
                        time.sleep(0.5)
                        ssh_cli.send('no tacacs-server host 10.0.0.172\n'.encode())
                        time.sleep(0.5)
                        ssh_cli.send('exit\n'.encode())
                        time.sleep(0.5)
                        ssh_cli.send('wr\n'.encode())
                        time.sleep(1)
                    elif re.search(r'\b10.0.3.14\b', result):
                        time.sleep(0.5)
                        print(f'{ipaddress}: tacacs server is already new')
                    elif re.search(r'\b\b', result):
                        time.sleep(0.5)
                        print('Tacacs server is not configured')

                    print(result)
                    client.close()
                elif vendor == "Hua":
                    time.sleep(1)
                    ssh_cli.send('screen-length 0 temporary\n'.encode())
                    time.sleep(1)
                    ssh_cli.send('dis cur | i hwtacacs server authentication\n'.encode())

                    # This timer needed for buffered result in "result"
                    time.sleep(3)

                    result = ssh_cli.recv(99999).decode('ascii')

                    if re.search(r'\b10.0.0.172\b', result):
                        print(f'{ipaddress}: tacacs server is old version')
                    elif re.search(r'\b10.0.3.14\b', result):
                        print(f'{ipaddress}: tacacs server is already new')
                    elif re.search(r'\b\b', result):
                        print(f'{ipaddress}: tacacs server is not configured')

                    print(result)
                    client.close()
        except Exception as commands_error:
            print(f"\nError commands to {ipaddress}: {commands_error}")
        print(colors.BOLD + f"\nEnd {ipaddress}" + colors.ENDC)
    else:
        print(f"What's wrong: device {ipaddress} is not support or your community is wrong")


# Start script execution
if __name__ == '__main__':
    device_ip_list = get_ip_list()
    print(*device_ip_list)
    #    ssh_connect(device_ip_list, 'sh int desc\nsh ver\n')
    multiprocessing.set_start_method("spawn")
    with multiprocessing.Pool(maxtasksperchild=3) as process_pool:
        routers_with_issues = process_pool.map(ssh_connect, device_ip_list,
                                               1)  # ssh_connect - function, device_ip_list - argument
        process_pool.close()
        process_pool.join()

    # Print end time work
    print(colors.BOLD + f"\n{datetime.now() - start_time}" + colors.ENDC)
