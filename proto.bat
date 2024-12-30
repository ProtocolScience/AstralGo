@echo off
setlocal enabledelayedexpansion

set PROTO_DIR=client/pb
set PROTO_OUTPUT_PATH=client
set PROTO_IMPORT_PATH=client
set PATH=%PATH%;C:\Users\yiran\go\bin
set PROTO_FILES=

rem 获取当前目录的绝对路径
set "currentDir=%cd%"

rem 遍历当前目录及其子目录中的所有文件
for /r "%currentDir%" %%f in (*.proto) do (
    rem 获取相对路径
    set "relPath=%%f"
    set "relPath=!relPath:%currentDir%\=!"
    ..\protoc\protoc.exe --golite_out=%PROTO_OUTPUT_PATH% --golite_opt=paths=source_relative -I=%PROTO_IMPORT_PATH% !relPath!
)

endlocal