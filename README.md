# POSHNetConMon

## Usage
Run the script from an elevated PowerShell instance. Two parameters are require [-IP] and [-Seconds]. 
IP address is the local IP address of your current machine and interface you would like to monitor on.
Seconds is how long the tool will run and monitor before analyzing and displaying data.

### Example

```
.\netConMon.ps1 -IP 192.168.1.1 -Seconds 10
