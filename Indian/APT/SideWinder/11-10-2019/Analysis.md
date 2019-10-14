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
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/extunsed.png)
### Same IP as C2 
###### Like the last analysis (in August 2019), the group use the same domain and IP as C2, we can observed that is probably active since may 2019.
|IP|Route|ASN|Organization|Country|City|Coordinates|
| :---------------: | :---------------: | :---------------: |:---------------: |:---------------: |:---------------: |:---------------: |
|178.62.190.33|178.62.128.0/18|AS14061|DigitalOcean, LLC|Netherlands|Amsterdam| 52.3740,4.8897|

![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/whois.png)
### Still continue to target China
###### Since the accord between China and Pakistan about the Kashmir crisis, the Indian APT SideWinder hasn't stopped attacking China, the last time this target the China event on the Chian's 2019 Defense White Paper and this time used to fake technical documentation.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/eventchina1.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/Pictures/October%202019/eventchina2.png)

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
|zhengce.doc|b1417d7ee62878ef75381e4a3a4f388ac08ac4d4bbd9999b126345691e82b0c2|
|C:\ProgramData\AuthyFiles\PROPSYS.dll|4e12d1bf1a631b8045e267671c0340b8da61777480692c4ce396f932f6bd4023|
|C:\ProgramData\AuthyFiles\write.exe|45BD87A5803916409A0D824BEEFAFB1FAF49D52E0BA9C0E8014E82EAA17E7659|
|1.a|c5feee527bb90926949c572bfe3fceb862727a9f5cee1fc580a11558253d624e|
|Authy|99542270c355bdaef251fefeaf88c5ff747e3837501735887e7b2b7b54e2e2f2|
|178.62.190.33|IP C2|
|trans-can.net|Domain C2|

###### This can be exported as JSON format [Export in JSON](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/11-10-2019/IOC-SideWinder-14-10-19.json)	

## Links <a name="Links"></a>
###### Original tweet: 
* [https://twitter.com/Timele9527/status/1182587382626996224](https://twitter.com/Timele9527/status/1182587382626996224) <a name="Original-Tweet"></a>
###### Links Anyrun: <a name="Links-Anyrun"></a>
* [zhengce.doc](https://app.any.run/tasks/7cdd1bfc-f0a3-4dd6-a29c-5ed70a77e76c)
