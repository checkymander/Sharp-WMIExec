# SharpInvoke-SMBExec
A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script. (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1)

Built for .NET 4.5

# Usage
Sharp-WMIExec.exe -h "hash" -u "username" -d "domain.tld" -t "target.domain.tld" -c "command"

# Description
This Assembly will allow you to execute a command on a target machine using WMI by providing an NTLM hash for the specified user.

# Help
```
GlobalOption     Description                                                                                            
Help (-?)                                                                                                               
Username* (-u)   Username to use for authentication                                                                     
Hash* (-h)       NTLM Password hash for authentication. This module will accept either LM:NTLM or NTLM format           
Domain (-d)      Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username
Target (-t)      Hostname or IP Address of the target.                                                                  
Command (-c)     Command to execute on the target. If a command is not specified, the function will check to see if the username and hash provide local admin access on the target
Sleep (-st)      Time in seconds to sleep. Change this value if you're getting weird results. [Default='15']            
Debug (-dbg)     Switch, Enabled debugging [Default='False']                                    
```
