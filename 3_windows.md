xfreerdp /v:<targetIp> /u:htb-student /p:Password

What port is `RDP` on?
3389

What is the maximum file size for fat32?
`4 GB`

What is the command for checking permissions on specific directories?
`icacls`, ei., `icacls C:\Windows`


    (CI): container inherit
    (OI): object inherit
    (IO): inherit only
    (NP): do not propagate inherit
    (I): permission inherited from parent container


    F : full access
    D :  delete access
    N :  no access
    M :  modify access
    RX :  read and execute access
    R :  read-only access
    W :  write-only access

What is the tool used for accessing system logs in Windows?
`Event Viewer`

How do you share a folder using SMB?
You go into advanced sharing options on the folder and share, there you can also control the ACL etc

What command should you use to display services? 
`Get-service -Displayname "*search_term*"`

how would you examine a service? 
lookup the service in `service.msc`, thereafter, run `sc.exe qc service_name`

How would you get permissions in Windows?
`Get-Acl`
```
Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List
```

How do you get all of your aliases on the machine?
`Get-Alias`

How do you search for a specific alias?
`Get-Alias | findstr "ipconfig"`

Find the Execution Policy set for the LocalMachine scope. 
`Get-ExecutionPolicy -List`

How do you list information about the operation system?
`wmic os list brief`

What is the mame of windows management program?
`management.msc`

What is the Security identifier in Windows? (SID)

The user-specific registry hive (HKCU) is stored in the user folder:
`C:\Windows\Users\<USERNAME>\Ntuser.dat`

How do you check what protection setting is enabled?
`Get-MpComputerStatus | findstr "True"`

Find the SID of the bob.smith user. 
`wmic useraccount get name,sid`

