# The campaign of FIN7 group continue
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Originals Tweets](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Documents](#Documents)
## Malware analysis <a name="Malware-analysis"></a>
###### The initial vector is a malicious xls which use a macro for extracts from the strings on the document the js script and execute it.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/Macro.png)
###### The first layer of the JS loader is a series of arrays where the second elements are used for giving the second layer of the loader.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer1.png)
###### The first functions executed in the second layer is encoding the data to send at the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20decode.png)
##### The main sends a pulse to the C2 and wait for the instructions to perform.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20main.png)
###### The loader performs a discover action for list the DNS host of the list active network cards. This helps to prepare the DNS extraction for sending the data in the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20id.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20id.png)

###### This use after a function for randomizing (4 letters or numbers) the sub part of the URL to domain the contact and the name of file for storage temporary the data in waiting to send it(as tmp file in the disk).
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20ns.png)
###### In function of the hard-coded mode in loader, this sends the data via a DNS extraction or via HTTP.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20send.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/layer2%20-%20dnsext.png)
###### If the target is interesting, the group can perform custom commands and execute a backdoor on the computer. The IP used as C2 rest the same that the samples spotted early September.
|IP|Route|ASN|Organization|Country|City|Coordinates|
| :---------------: | :---------------: | :---------------: |:---------------: |:---------------: |:---------------: |:---------------: |
|185.231.153.21| 185.231.153.0/24|AS48282|VDSINA VDS Hosting|Russia|Moscow|55.7386,37.6068|
## Cyber kill chain <a name="Cyber-kill-chain"></a>
###### The process graphs resume all the cyber kill chains used by the attacker. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Pictures/CyberKill.png)

## Indicators Of Compromise (IOC) <a name="IOC"></a>
###### List of all the Indicators Of Compromise (IOC)

|Indicator|Description|
| ------------- |:-------------|
|order.xlsb|2ba6709be053eb456c7fbe0c7e19196fefc7fe93afaea1e008c417aa6faeeeb3|
|umyhpakixg.txt|980b6ec3e3fc3d25af8273e8c85142c551875a472cc900e427b9c4cb87e59d39|
|e5ac4108d02499fbdb8e04aa8c42c3dd40cc6be02b4ceb12145075c8bd32b790.xls|e5ac4108d02499fbdb8e04aa8c42c3dd40cc6be02b4ceb12145075c8bd32b790|
|moviedvdpower.com|Domain requested|
|31.3.232.105|IP requested|
|185.231.153.21|IP C2|
|catering_list.xls|73d0b3cdff094bac4f965972a89872a11d60c5a58c0be9652d482808fa6d236e|
|wcykafy.exe|bd7b57a9303f0156e0737e9768a70f841b222a3e07e1426ecccfffdf2737bfe9|
|moviedvdpower.com|Domain C2|
|31.3.232.105|IP C2|
|8dd588a49d4e2c20a2c97f3726c0d2d85c5f6d402206c1f6dd2b33aea58565fc.exe|8dd588a49d4e2c20a2c97f3726c0d2d85c5f6d402206c1f6dd2b33aea58565fc|
|8773aeb53d9034dc8de339651e61d8d6ae0a895c4c89b670d501db8dc60cd2d0.dll|8773aeb53d9034dc8de339651e61d8d6ae0a895c4c89b670d501db8dc60cd2d0|
|DWrite.dll|18cc54e2fbdad5a317b6aeb2e7db3973cc5ffb01bbf810869d79e9cb3bf02bd5|
|Malware.doc|ee0cb9e6de83f807ccf9c3a02b384c1fb6e59f7de720f1eaf37141bf0487f5e6|
|Screenshot + payment.doc|75a75224e81423663dd66ce20f845a58d523b0948c9d5cf135d599324512103e|
|doc1.doc|860a5e83c509ec6615a722cd62ba47a506f115743eeb03cc94b3d2b03cc0ecc0|

###### This can be exported as JSON format [Export in JSON](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/Cybercriminal%20group/FIN7/16-10-19/IOC-FIN7-16-10-19.json)	

## References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a>
###### List of all the references with MITRE ATT&CK Matrix

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Defense Evasion|Scripting|https://attack.mitre.org/techniques/T1064/|
|Execution|Scripting|https://attack.mitre.org/techniques/T1064/|
|Defense Evasion|Install Root Certificate|https://attack.mitre.org/techniques/T1130/|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/|

## Links <a name="Links"></a>
###### Original tweet: 
* [https://twitter.com/Rmy_Reserve/status/1184142117284667393](https://twitter.com/Rmy_Reserve/status/1184142117284667393) <a name="Original-Tweet"></a>
###### Links Anyrun: <a name="Links-Anyrun"></a>
* [e5ac4108d02499fbdb8e04aa8c42c3dd40cc6be02b4ceb12145075c8bd32b790.xls](https://app.any.run/tasks/f2454e33-3d31-48a4-b49a-1b5c50eb7182)
* [order.xlsb](https://app.any.run/tasks/43371f0f-35d0-4d1d-a0f3-4c8e41cd31c8)
###### Documents:<a name="Documents"></a>
* [FIN7.5: the infamous cybercrime rig “FIN7” continues its activities](https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/)
* [Mahalo FIN7: Responding to the Criminal Operators’ New Tools and Techniques](https://www.fireeye.com/blog/threat-research/2019/10/mahalo-fin7-responding-to-new-tools-and-techniques.html)
* [FIN7 JS Backdoor](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Russia/Cybercriminal%20group/FIN7/16-10-19/Code/FIN7.js)
