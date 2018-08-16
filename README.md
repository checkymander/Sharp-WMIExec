# Sharp-InvokeWMIExec
A native C# conversion of Kevin Robertsons Invoke-WMIExec powershell script.

Currently built for .NET 4.5.2 (TODO Build for .NET 3.5)

# Requirements
Mono.Options (https://www.nuget.org/packages/Mono.Options/5.3.0.1)

# Usage
Sharp-InvokeWMIExec.exe -h="hash" -u="domain.com\username" -t="target.domain.com" -c="command"
