# DisableWinDefend by Zoic

Powershell script to disable Windows Defender on Latest Versions of 10 and 11

---------------------------------------------------------------------------------------------

- Newest update to Windows Defender makes it impossible to disable MsMpEng without disabling Tamper Protection before

- The script will automatically navigate to tamper protection via the security health app
  - You can also disable tamper protection before running the script

- Credits to @AveYo for the disable MsMpEng service snippet 

NOTE: When running on Windows 11 you must run the "RunScript11" file with DisableDefender.ps1 in the same directory
