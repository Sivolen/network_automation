import os
import re
import time
import logging
import multiprocessing

# from pysnmp.hlapi import *
from pysnmp.hlapi import (
    getCmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)
from datetime import datetime
from logging.handlers import RotatingFileHandler

# from socket import socket

import netsnmp
import paramiko

from settings import *

# Start time at work
start_time = datetime.now()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_header = RotatingFileHandler("logs/debug.log", maxBytes=100000, backupCount=100)
file_header.setLevel(logging.DEBUG)
log_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_header.setFormatter(log_format)
logger.addHandler(file_header)


# Checking ipaddresses
def check_ip(ipaddress):
    check_ipaddress = re.findall(
        r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1"
        "[0-9]"
        "{2}|2[0-4]["
        "0-9]|25[0-5])$",
        ipaddress,
    )
    return ipaddress if check_ipaddress else False


# Get ip list from file
def get_ip_list():
    try:
        return [
            line.replace("\n", "")
            for line in open("ip").readlines()
            if check_ip(ipaddress=line) is not None
        ]
    except IOError:
        logger.debug("File do not open because ip file does not exist")


# SNMP connection to device for get_device_id
def snmp_connection(ip, community):
    time.sleep(1)
    oid = netsnmp.Varbind(".1.3.6.1.2.1.1.1")
    # print(oid, ip_full, community)  # Debug option
    snmp_res = netsnmp.snmpwalk(oid, Version=2, DestHost=ip, Community=community)
    return snmp_res


def snmp_connect(ip):
    res = None
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community1),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community2),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    for varBind in varBinds:  # SNMP response contents
        res = " = ".join([x.prettyPrint() for x in varBind])
    return res


# Get device vendor from snmp
def get_device_id(ipaddress):
    snmp_walk = ""
    print(f"analyze device {ipaddress}")
    try:
        # snmp_walk = snmp_walk(oids='1.3.6.1.2.1.1.1', hostname=ipaddreess, community=community1, version=2)
        snmp_walk = snmp_connect(ip=ipaddress)
        # snmp_walk = snmp_connection(ipaddress, community1)
        # if snmp_walk == ():
        #     snmp_walk = snmp_connection(ipaddress, community2)
    except Exception as snmp_error:
        logger.debug(f"{ipaddress}: snmp connections error " + str(snmp_error))
    if re.search(r"\bCisco\b", str(snmp_walk)):
        return "Cisco"
    elif re.search(r"\bHuawei\b", str(snmp_walk)) or re.search(
        r"\bHUAWEI\b", str(snmp_walk)
    ):
        return "Hua"
    elif re.search(r"", str(snmp_walk)):
        return None


# Function ssh connectivity and sensing device commands without multiprocessing
def connecting_to_devices(ipaddress):
    status = ""
    vendor = get_device_id(ipaddress)
    if vendor is not None:
        logger.debug(
            colors.BOLD + f"\nStart connection to: {ipaddress} ({vendor})" + colors.ENDC
        )
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ipaddress,
                username=user,
                password=password,
                port=port,
                look_for_keys=False,
                allow_agent=False,
                timeout=10,
            )
        # except (paramiko.AuthenticationException,
        #         paramiko.ssh_exception.NoValidConnectionsError,
        #         paramiko.SSHException,
        #         socket.timeout) as connection_error:
        except Exception as connection_error:
            logger.debug(
                colors.FAIL
                + f"\nError connecting to {ipaddress}: {connection_error}"
                + colors.ENDC
            )
            status = connection_error
        try:
            with client.invoke_shell() as ssh_cli:
                if vendor == "Cisco":
                    ssh_cli.send("terminal length 0\n".encode())
                    time.sleep(1)
                    ssh_cli.send("conf t\n".encode())
                    time.sleep(0.5)
                    ssh_cli.send("err rec ca all\n".encode())
                    time.sleep(0.5)
                    ssh_cli.send("err rec int 60\n".encode())
                    time.sleep(0.5)
                    ssh_cli.send(
                        "no spanning-tree etherchannel guard misconfig\n".encode()
                    )
                    time.sleep(0.5)
                    ssh_cli.send("aaa authorization console\n".encode())
                    time.sleep(0.5)
                    ssh_cli.send("no enable password\n".encode())
                    time.sleep(0.5)
                    ssh_cli.send("enable secret z5WRgV8AfsFa\n".encode())
                    time.sleep(0.5)
                    # for interface in open('int').readlines():
                    #
                    #     ssh_cli.send(f'int {interface}\n'.encode())
                    #     time.sleep(0.5)
                    #     ssh_cli.send('no desc\n'.encode())
                    #     time.sleep(0.5)
                    ssh_cli.send("exit\n".encode())
                    time.sleep(0.5)
                    ssh_cli.send("wr\n".encode())
                    time.sleep(0.5)
                    # ssh_cli.send('wr\n'.encode())

                    # This timer needed for buffered result in "result"
                    result = ssh_cli.recv(99999).decode("ascii")

                    if re.search(r"\bntp logging\b", result):
                        time.sleep(0.5)
                        logger.debug(f"ntp is old")
                        ssh_cli.send("conf t\n".encode())
                        time.sleep(0.5)
                        ssh_cli.send("no ntp logging\n".encode())
                        time.sleep(0.5)
                        ssh_cli.send("no ntp clock-period\n".encode())
                        time.sleep(0.5)
                        ssh_cli.send("exit\n".encode())
                        time.sleep(0.5)
                        ssh_cli.send("wr\n".encode())
                        time.sleep(5)
                        status = "NTP changed"
                    elif re.search(r"\b\b", result):
                        time.sleep(0.5)
                        status = "NTP is new"
                        logger.debug("NTP is new")
                    print(result)
                    client.close()
                elif vendor == "Hua":
                    time.sleep(1)
                    ssh_cli.send("screen-length 0 temporary\n".encode())
                    time.sleep(1)
                    ssh_cli.send("dis cur | i 10.230.\n".encode())
                    # This timer needed for buffered result in "result"
                    time.sleep(4)

                    result = ssh_cli.recv(99999).decode("ascii")

                    if re.search(r"\b10.230.\b", result):
                        logger.info(f"{ipaddress}: ntp server is old version")
                        status = "NTP changed"
                    elif re.search(r"\b\b", result):
                        logger.info(f"{ipaddress}: ntp server is not configured")
                        status = "NTP is new"
                    print(result)
                    client.close()

        except Exception as commands_error:
            logger.debug(f"\nError commands to {ipaddress}: {commands_error}")
        logger.debug(colors.BOLD + f"\nEnd {ipaddress}" + colors.ENDC)
    else:
        status = "snmp error"
        logger.debug(
            f"What's wrong: device {ipaddress} is not support or your community is wrong"
        )

    if vendor == "Hua" and status == "NTP changed":
        with open("progress_hua", "a") as file:
            file.writelines(f"ip: {ipaddress}, vendor: {vendor}, status: {status}\n")
            file.close()

    elif vendor == "Cisco" and status == "NTP changed":
        with open("progress_cisco", "a") as file:
            file.writelines(f"ip: {ipaddress}, vendor: {vendor}, status: {status}\n")
            file.close()

    # elif status == 'Updated':
    else:
        with open("progress", "a") as file:
            file.writelines(f"ip: {ipaddress}, vendor: {vendor}, status: {status}\n")
            file.close()


# Main funktion, init multiprocess
def main():
    device_ip_list = get_ip_list()
    # print(*device_ip_list)

    if os.path.exists("progress_hua"):
        os.remove("progress_hua")
    if os.path.exists("progress_cisco"):
        os.remove("progress_cisco")
    if os.path.exists("progress"):
        os.remove("progress")

    multiprocessing.set_start_method("spawn")
    with multiprocessing.Pool(maxtasksperchild=1) as process_pool:
        # ssh_connect - function, device_ip_list - argument
        process_pool.map(connecting_to_devices, device_ip_list, 3)

        process_pool.close()
        process_pool.join()
    # view_progress()


# View progress after script completed
def view_progress():
    with open("progress", encoding="utf-8", errors="ignore") as file:
        for line in file.readlines():
            print(line)


# Start script execution
if __name__ == "__main__":
    main()

    # Print end time work
    print(colors.BOLD + f"\n{datetime.now() - start_time}" + colors.ENDC)
