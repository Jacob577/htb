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

## Important to remember: there are --scripts to nmap, such as smb scripts and so forth, another great script is 'banner'. 

A good script to include in nmap is: `--scripts vuln`:
```bash
sudo nmap 10.129.2.28 -p 80 -sV --script vuln 
```

