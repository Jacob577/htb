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