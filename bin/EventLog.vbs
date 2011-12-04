Dim objFSO

strComputer = "."
directory = Wscript.Arguments(0)

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set oShell = CreateObject("Wscript.Shell")


Set objWMIService = GetObject("winmgmts:" _
    & "{impersonationLevel=impersonate,(Backup)}!\\" _
        & strComputer & "\root\cimv2")
Set colLogFiles = objWMIService.ExecQuery _
    ("Select * from Win32_NTEventLogFile " _
        & "Where LogFileName='Application'")
For Each objLogfile in colLogFiles
    errBackupLog = objLogFile.BackupEventLog( _
         directory & "\Application.evt")
Next

WScript.Sleep 60

Set objWMIService = GetObject("winmgmts:" _
    & "{impersonationLevel=impersonate,(Backup)}!\\" & _
        strComputer & "\root\cimv2")
Set colLogFiles = objWMIService.ExecQuery _
    ("Select * from Win32_NTEventLogFile " _
        & "Where LogFileName='System'")
For Each objLogfile in colLogFiles
    errBackupLog = objLogFile.BackupEventLog( _
        directory & "\System.evt")
Next

WScript.Sleep 60