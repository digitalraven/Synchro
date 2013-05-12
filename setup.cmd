REM Piece of pish synchro install script
REM All I need are the actual exes
REM Running them with Python and options would cause more headaches

mkdir "c:\Program Files\Synchro"
copy *.exe "C:\Program Files\Synchro"
reg add HKLM\Software\Synchro\Config /v InstallDir /t REG_SZ /d "c:\Program Files\Synchro"