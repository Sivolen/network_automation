Script for automated configuration of network devices.
This script changet ip address for tacacs+ server for cisco and huawei devices but you can change ssh_connect function and added there your settings.

First if you want to script work, you need to create file named ip in the root directory. 
Second you need to edit settings.py, add your username & password for ssh and community for snmp. 
I'm usually using two community because first community this is new community, second community is old.
If you don't need second community, community2 leave the field blank.