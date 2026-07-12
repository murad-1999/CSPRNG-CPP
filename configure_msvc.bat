@echo off
rem Configure the project using CMake and MSVC NMake Generator
echo Configuring CSPRNG-CPP with CMake using NMake Makefiles generator...
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release .
if %errorlevel% neq 0 (
    echo Configuration failed. Make sure you are running from the Developer Command Prompt for VS.
    exit /b %errorlevel%
)
echo Configuration successful. Run 'nmake' to build.
