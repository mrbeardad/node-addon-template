cd %~dp0
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
call pnpm install --ignore-scripts
call pnpm clean
call pnpm build
