set PY_INST=c:\python27_32bit\Scripts\pyinstaller.exe

rmdir /S /Q dist

%PY_INST% --icon img\SPLiT.ico --onefile --clean --distpat=dist --console SPLiT.py

cd dist

rename SPLiT.exe SPLiT_w32.exe
pause