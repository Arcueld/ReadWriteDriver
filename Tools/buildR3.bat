set "currentPath=%cd%"
cd ../
set "projectPath=%cd%"
cd %currentPath%
set "buildPath=%projectPath%\Release\Loader.sys"
"%projectPath%\Tools\BuilderR3.exe" %buildPath% sys.h payload