$EXECUTABLE_NAME="main"
$EXECUTABLE_PATH=".\"
$GoPath=((go env | Select-String -Pattern "GOPATH=" | Out-String) -split "=")[1].TrimEnd()
$GoPath+="\bin"
Set-Location $EXECUTABLE_PATH
Start-Process go -ArgumentList "build -o $EXECUTABLE_NAME.exe -gcflags `"-N -l`" " -Wait -NoNewWindow # compile without optimizations and inlining
Start-Process ".\$EXECUTABLE_NAME.exe"
$timeOut = 20
$started = $false
# wait for process to start
Do {
    Start-Sleep -Milliseconds 250
    $timeOut--
    $Proc = Get-Process main -ErrorAction SilentlyContinue
    If ($Proc) { 
        $started = $true 
    }
}
Until ($started -or $timeOut -eq 0)
If (!($started)) {
    Write-Error 'Process did not start' 
    Exit
}
$ProcId=($Proc | Select-Object -expand Id)
Start-Process -FilePath "$GoPath\dlv.exe" -ArgumentList "attach $ProcId --headless --listen=:2345 --log" -WindowStyle Hidden