echo Windows Registry Editor Version 5.00 > USBProv.reg
echo
echo [HKEY_LOCAL_MACHINE\SOFTWARE\USBCryptoProvider] >> USBProv.reg
echo "KeyFolderPath"="%1">> USBProv.reg

regedit USBProv.reg