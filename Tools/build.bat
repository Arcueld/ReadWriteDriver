set "currentPath=%cd%"
cd ../
set "projectPath=%cd%"
cd %currentPath%
set "buildPath=%projectPath%\Release\TestDriver.sys"
"%projectPath%\Tools\Builder.exe" %buildPath% sys.h sysData