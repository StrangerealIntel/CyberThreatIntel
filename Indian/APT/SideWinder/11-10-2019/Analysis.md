# The SideWinder campaign continue
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber Threat Intel](#Cyber-Threat-Intel)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)

## Malware analysis <a name="Malware-analysis"></a>
###### The initial vector is a malicious RTF file with an RTF exploit (CVE-2017-11882) for executing the package OLE from the doc.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/obj.PNG)
###### The first part of the JS payload is a function for decode the payload and resize the windows for hidden of the victim and is decoding the PE files in base 64.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/jspay1.PNG)
###### On the second part, this extracts the files on "C:\ProgramData\AuthyFiles\" and use a function for detecting the version of NET for use the correct version of csc to use. Once this done, this uses the even tactical that the last time in using deserialized the serialized objects and push it by a "DynamicInvoke" in the current delegate.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/jspay2.PNG)
###### In the final part, this executes it in the memory the legit file (writer.exe -> Windows Write of Microsoft), the loader and the payload of the hijack.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/jspay3.PNG)
###### The loader copy a part of the payload and push in create a new process from the "write" process by process hijacking. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/dll1.PNG)
###### This push an Run key or the persistence, show an error message for decoys the victims. This steals the configuration (Admin rights, IP config, system config, time zone, process, updates...), the list of documents on the disk and sent it to the C2 and wait for the commands.
## Cyber Threat Intel <a name="Cyber-Threat-Intel"></a>
### Files push in Appdata
###### The backdoor stock in the disk multiples files with differents results of the operations perform on the computer:
 + A file with a sif extension :
###### This content the system and user account informations steal by the backdoor and which send to the C2 when the connection is etablish (JSON file).
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/ext1.png)
+ Another file with the fls extension :
###### A second JSON file which content the list of the path of the document to steal and push on the C2 (target the xls, xlsx, doc, docx, pdf documents).
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/ext2.png)
###### A file with the extension flc is used by the process as debug for the edition of the fls file.
### Same IP as C2 

## Cyber kill chain <a name="Cyber-kill-chain"></a>
###### The process graphs resume all the cyber kill chains used by the attacker. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/CyberKill.png)
## References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a>
###### List of all the references with MITRE ATT&CK Matrix

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Execution through Module Load<br>Exploitation for Client Execution|https://attack.mitre.org/techniques/T1129/<br>https://attack.mitre.org/techniques/T1203/|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060/|
|Credential Access|Credentials in Files|https://attack.mitre.org/techniques/T1081/|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/|

## Indicators Of Compromise (IOC) <a name="IOC"></a>
###### List of all the Indicators Of Compromise (IOC)
|Indicator|Description|
| ------------- |:-------------:|
|||

###### This can be exported as JSON format [Export in JSON]()	

## Links <a name="Links"></a>
###### Original tweet: 
* [https://twitter.com/Timele9527/status/1182587382626996224](https://twitter.com/Timele9527/status/1182587382626996224) <a name="Original-Tweet"></a>
###### Links Anyrun: <a name="Links-Anyrun"></a>
* [zhengce.doc](https://app.any.run/tasks/7cdd1bfc-f0a3-4dd6-a29c-5ed70a77e76c)
