# SharpInvoke-SMBExec
A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script. (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1)

Built for .NET 4.5

# Pre-Built version of the binary can be found in the releases, with all applicable references included.

# Usage
Sharp-SMBExec.exe -h="hash" -u="domain.com\username" -t="target.domain.com" -c="command"

# Description
This Assembly will allow you to execute a command on a target machine using SMB by providing an NTLM hash for the specified user.
