# SharpInvoke-WMIExec
A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script. (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-WMIExec.ps1)

Built for .NET 3.5

# Usage
Sharp-WMIExec.exe hash:<hash> username:<username> domain:<domain> target:<target> command:<command>

# Description
This Assembly will allow you to execute a command on a target machine using WMI by providing an NTLM hash for the specified user.

# Help
```
Option		    Description                                                                                                                                                                                                      
username*		Username to use for authentication                                                                     
hash*			NTLM Password hash for authentication. This module will accept either LM:NTLM or NTLM format           
domain			Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username
target			Hostname or IP Address of the target.                                                                  
command			Command to execute on the target. If a command is not specified, the function will check to see if the username and hash provide local admin access on the target         
-CheckAdmin     Check admin access only, don't execute command
-Help (-h)		Switch, Enabled debugging [Default='False']  
-Debug			Print Debugging Information along with output
```
