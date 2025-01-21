set "currentPath=%cd%"
cd ../
set "projectPath=%cd%"
cd %currentPath%
set "buildPath=%projectPath%\x64\Release\TestDriver.sys"
"%projectPath%\Tools\Builder.exe" %buildPath% sys.h sysData