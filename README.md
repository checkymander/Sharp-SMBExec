# SharpInvoke-SMBExec
A native C# conversion of Kevin Robertsons Invoke-SMBExec powershell script. (https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1)

Built for .NET 4.5

# Usage
Sharp-SMBExec.exe -h "hash" -u "username" -d "domain.tld" -t "target.domain.tld" -c "command" -cc 

# Description
This Assembly will allow you to execute a command on a target machine using SMB by providing an NTLM hash for the specified user.

# Help
```
Sharp-SMBExec.exe -h "hash" -u "username" -d "domain.tld" -t "target.domain.tld" -c "command" -cc
Help (-?)                                                                                                               
Username* (-u)   Username to use for authentication                                                                     
Hash* (-h)       NTLM Password hash for authentication. This module will accept either LM:NTLM or NTLM format           
Domain (-d)      Domain to use for authentication. This parameter is not needed with local accounts or when using @domain after the username
Target (-t)      Hostname or IP Address of the target.                                                                  
Command (-c)     Command to execute on the target. If a command is not specified, the function will check to see if the username and hash provide local admin access on the target
Service (-s)     Default = 20 Character Random. The Name of the service to create and delete on the target.             
ComSpec (-cc)    Prepend %COMSPEC% /C to Command [Default='False']                                  
SMB1 (-v1)       Force SMB1. The default behavior is to perform SMB Version negotiation and use SMB2 if it's supported by the target [Default='False']
Sleep (-st)      Time in seconds to sleep. Change this value if you're getting weird results. [Default='15']            
Debug (-dbg)     Switch, Enable debugging [Default='False']                              
```
