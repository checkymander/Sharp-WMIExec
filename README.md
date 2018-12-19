# Sharp-InvokeWMIExec
A native C# conversion of Kevin Robertsons Invoke-WMIExec powershell script.

Built for .NET 4.5

# Pre-Built version of the binary can be foudn in the releases, with all applicable references included.

# Usage
Sharp-WMIExec.exe -h="hash" -u="domain.com\username" -t="target.domain.com" -c="command"

# Description
This Assembly will allow you to execute a command on a target machine using WMI by providing an NTLM hash for the specified user.
