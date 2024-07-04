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