@echo off
REM Script to run WildFly with port offset

set WILDFLY_HOME=C:\Users\boula\Downloads\wildfly-39.0.0.Beta1\wildfly-39.0.0.Beta1
set PORT_OFFSET=2020

echo Starting WildFly with port offset %PORT_OFFSET%...
echo.

cd /d "%WILDFLY_HOME%\bin"
standalone.bat -Djboss.socket.binding.port-offset=%PORT_OFFSET%

echo.
echo WildFly stopped.
pause
