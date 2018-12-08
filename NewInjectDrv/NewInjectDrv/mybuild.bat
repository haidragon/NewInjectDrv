set ddkpath=%~d0\WinDDK\3790.1830
set curpath=%CD%
call %ddkpath%\bin\setenv.bat %ddkpath% fre
cd /d %curpath%
build -zcw

