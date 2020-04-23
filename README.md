# SharpInvoke-SMBExec
A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script. (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1)

Built for .NET 3.5

# Usage
Sharp-SMBExec.exe hash:"hash" username:"username" domain:"domain.tld" target:"target.domain.tld" command:"command"

# Description
This Assembly will allow you to execute a command on a target machine using SMB by providing an NTLM hash for the specified user.

# Help
```
Option		    Description                                                                                                                                                                                                      
username*		Username to use for authentication                                                                     
hash*			NTLM Password hash for authentication. This module will accept either LM:NTLM or NTLM format           
domain			Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username
target			Hostname or IP Address of the target.                                                                  
command			Command to execute on the target. If a command is not specified, the function will check to see if the username and hash provide local admin access on the target    
ServiceName		Default = 20 Character Random. The Name of the service to create and delete on the target.  
-CheckAdmin       Check admin access only, don't execute command
-Help (-h)		Switch, Enabled debugging [Default='False']  
-Debug			Print Debugging Information along with output
-ForceSMB1		Force SMB1. The default behavior is to perform SMB Version negotiation and use SMB2 if it's supported by the target [Default='False']
-ComSpec		Prepend %COMSPEC% /C to Command [Default='False']  
```
