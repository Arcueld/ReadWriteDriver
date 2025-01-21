set "currentPath=%cd%"
cd ../
set "projectPath=%cd%"
cd %currentPath%
set "buildPath=%projectPath%\Release\TestDriver.sys"
"%projectPath%\Tools\BuilderR3.exe" %buildPath% sys.h payload