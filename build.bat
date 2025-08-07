cd %~dp0
call pnpm install --ignore-scripts
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 10.0.22621.0 -vcvars_ver=14.38
call pnpm configure --msvs_version=2022 --arch=x64 --target=33.2.0 --dist-url=https://electronjs.org/headers --devdir=%USERPROFILE%\.electron-gyp
msbuild .\build\binding.sln /p:Configuration=Release;UseEnv=true
