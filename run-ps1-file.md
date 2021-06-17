PowerShell has four execution policies that govern how it should execute scripts:

- Restricted. PowerShell won't run any scripts. This is PowerShell's default execution policy.
- AllSigned. PowerShell will only run scripts that are signed with a digital signature. If you run a script signed by a publisher PowerShell hasn't seen before, PowerShell will ask whether you trust the script's publisher.
- RemoteSigned. PowerShell won't run scripts downloaded from the Internet unless they have a digital signature, but scripts not downloaded from the Internet will run without prompting. If a script has a digital signature, PowerShell will prompt you before it runs a script from a publisher it hasn't seen before.
- Unrestricted. PowerShell ignores digital signatures but will still prompt you before running a script downloaded from the Internet.

To display the current execution policy, you need to enter the command

```
Get-ExecutionPolicy
```

at a PowerShell prompt (which will look like PS C:\> assuming the current location is C:\). To set the execution policy, enter the command

```
Set-ExecutionPolicy <policy>
```

where policy is one of the policy names (e.g., RemoteSigned).

```
Set-ExecutionPolicy RemoteSigned
```

> P/S: Operator (&) allows you to execute a command, script or function.
