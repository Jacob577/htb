## Use Cases:

    Audit the security aspects of networks
    Simulate penetration tests
    Check firewall and IDS settings and configurations
    Types of possible connections
    Network mapping
    Response analysis
    Identify open ports
    Vulnerability assessment as well.
## Nmap architecture

    Host discovery
    Port scanning
    Service enumeration and detection
    OS detection
    Scriptable interaction with the target service (Nmap Scripting Engine)

### Other:
For example, the TCP-SYN scan (-sS) is one of the default settings unless we have defined otherwise and is also one of the most popular scan methods. This scan method makes it possible to scan several thousand ports per second. The TCP-SYN scan sends one packet with the SYN flag and, therefore, never completes the three-way handshake, which results in not establishing a full TCP connection to the scanned port.

    If our target sends an SYN-ACK flagged packet back to the scanned port, Nmap detects that the port is open.
    If the packet receives an RST flag, it is an indicator that the port is closed.
    If Nmap does not receive a packet back, it will display it as filtered. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.

<b>To scan network ranges</b>
```bash
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

    10.129.2.0/24 	Target network range.
    -sn 	Disables port scanning.
    -oA tnet 	Stores the results in all formats starting with the name 'tnet'.

<b>To save the nmap scan, use `-il <file_name>`:</b>
```bash
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
    -sn 	Disables port scanning.
    -oA tnet 	Stores the results in all formats starting with the name 'tnet'.
    -iL 	Performs defined scans against targets in provided 'hosts.lst' list.

<b>To check if the host is alive:</b>
```bash
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace 
```

    10.129.2.18 	Performs defined scans against the target.
    -sn 	Disables port scanning.
    -oA host 	Stores the results in all formats starting with the name 'host'.
    -PE 	Performs the ping scan by using 'ICMP Echo requests' against the target.
    --packet-trace 	Shows all packets sent and received

<b>Another great option with nmap is trace packets</b>
```bash
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping
```
    10.129.2.28 	Scans the specified target.
    -p 21 	Scans only the specified port.
    --packet-trace 	Shows all packets sent and received.
    -n 	Disables DNS resolution.
    --disable-arp-ping 	Disables ARP ping.

To see if we can establish a full TCP connection, use: `-sT`, a bit more aggressive.

To make an UDP scan, use the flag: `-sU`
```bash
sudo nmap 10.129.2.28 -F -sU
```
    10.129.2.28 	Scans the specified target.
    -F 	Scans top 100 ports.
    -sU 	Performs a UDP scan.
x
To scan a smb share:
```bash
sudo nmap --script smb-os-discovery.nse <IP> 

# Enumerate over hostname:
sudo nmap -A --top-ports=20 <IP>
```

### Save results from nmap:
```bash
# XML
-oX

# .nmap
-oN

# .gnmap
-oG
```

To furthermore convert results to HTML: `xsltproc target.xml -o target.html`

To increase verbosity of the scan, use: `-v`

<b>We can include tcpdump in our attacks</b>
```bash
sudo tcpdump -i eth0 host 10.10.14.2 and 10.129.2.28
```

## Important to remember: there are --scripts to nmap, such as smb scripts and so forth, another great script is 'banner', 'http-enum'. 

A good script to include in nmap is: `--scripts vuln`:
```bash
sudo nmap 10.129.2.28 -p 80 -sV --script vuln 
```

<b>Enumerate over http with: `http-enum`</b>


## Performance
Optimized RTT
```bash
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```
    10.129.2.0/24 	Scans the specified target network.
    -F 	Scans top 100 ports.
    --initial-rtt-timeout 50ms 	Sets the specified time value as initial RTT timeout.
    --max-rtt-timeout 100ms 	Sets the specified time value as maximum RTT timeout.

<b>Max retries</b>
```bash
sudo nmap 10.129.2.0/24 -F --max-retries 0 | grep "/tcp" | wc -l
```
    10.129.2.0/24 	Scans the specified target network.
    -F 	Scans top 100 ports.
    --max-retries 0 	Sets the number of retries that will be performed during the scan.

<b>Another optimized scan example</b>
```bash
sudo nmap 10.129.2.0/24 -F -oN tnet.minrate300 --min-rate 300
```
    10.129.2.0/24 	Scans the specified target network.
    -F 	Scans top 100 ports.
    -oN tnet.minrate300 	Saves the results in normal formats, starting the specified file name.
    --min-rate 300 	Sets the minimum number of packets to be sent per second.

<b>Optimized scan - Found open ports</b>
```bash
cat tnet.default | grep "/tcp" | wc -l
cat tnet.minrate300 | grep "/tcp" | wc -l
```

    -T 0 / -T paranoid
    -T 1 / -T sneaky
    -T 2 / -T polite
    -T 3 / -T normal
    -T 4 / -T aggressive
    -T 5 / -T insane

<b>Different scans</b>
```bash

# Default
sudo nmap 10.129.2.0/24 -F -oN tnet.default 

# Insane 
sudo nmap 10.129.2.0/24 -F -oN tnet.T5 -T 5
```

    10.129.2.0/24 	Scans the specified target network.
    -F 	Scans top 100 ports.
    -oN tnet.T5 	Saves the results in normal formats, starting the specified file name.
    -T 5 	Specifies the insane timing template.

<b>Analyzing results</b>
```bash

# Defaults
cat tnet.default | grep "/tcp" | wc -l

# Insane
cat tnet.T5 | grep "/tcp" | wc -l
```

## Firewall and IDS/IPS Evasion
IDS - Intrusion etection system
IPS - intrusion prevention system

SYN-scan
```bash
sudo nmap 10.129.2.28 -p 21,22,25 -sS -Pn -n --disable-arp-ping --packet-trace
```

ACK-scan
```bash
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```

    10.129.2.28 	Scans the specified target.
    -p 21,22,25 	Scans only the specified ports.
    -sS 	Performs SYN scan on specified ports.
    -sA 	Performs ACK scan on specified ports.
    -Pn 	Disables ICMP Echo requests.
    -n 	Disables DNS resolution.
    --disable-arp-ping 	Disables ARP ping.
    --packet-trace 	Shows all packets sent and received.

### Decoy
we can obfuscate our nmapping using `-D` for decoy, and will generate random IPs if ip subnets are blocked.

<b>Scan by using Decoy</b>
```bash
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

    10.129.2.28 	Scans the specified target.
    -p 80 	Scans only the specified ports.
    -sS 	Performs SYN scan on specified ports.
    -Pn 	Disables ICMP Echo requests.
    -n 	Disables DNS resolution.
    --disable-arp-ping 	Disables ARP ping.
    --packet-trace 	Shows all packets sent and received.
    -D RND:5 	Generates five random IP addresses that indicates the source IP the connection comes from.

<b>Testing firewall rule</b>
```bash
sudo nmap 10.129.2.28 -n -Pn -p445 -O

# Using different source IP
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
```

    10.129.2.28 	Scans the specified target.
    -n 	Disables DNS resolution.
    -Pn 	Disables ICMP Echo requests.
    -p 445 	Scans only the specified ports.
    -O 	Performs operation system detection scan.
    -S 	Scans the target by using different source IP address.
    10.129.2.200 	Specifies the source IP address.
    -e tun0 	Sends all requests through the specified interface.


<b>SYN-Scan</b>
```bash
# SYN-Scan of a Filtered Port
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace

SYN-scan from DNS Port
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

    10.129.2.28 	Scans the specified target.
    -p 50000 	Scans only the specified ports.
    -sS 	Performs SYN scan on specified ports.
    -Pn 	Disables ICMP Echo requests.
    -n 	Disables DNS resolution.
    --disable-arp-ping 	Disables ARP ping.
    --packet-trace 	Shows all packets sent and received.
    --source-port 53 	Performs the scans from specified source port.

<b>Connect to the filtered port</b>
```bash
ncat -nv --source-port 53 10.129.2.28 50000
```

<b>Get DNS server version:</b>
```bash
nmap -sSU -p53 --script dns-nsid <IP>
```

Remember to use nmap from dns port.... fml
```bash
sudo nmap <IP> -p- -sS -Pn -n --disable-arp-ping --source-port 53

# To connect
nc -nv -p 53 <IP> <port>
```

