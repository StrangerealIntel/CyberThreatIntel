# A Look into the Lazarus Group's Operations in October 2019
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [External analysis](#Analysis)

## Malware analysis <a name="Malware-analysis"></a>
###### The next analysis try to kept the recents events and a logicial improvement and technics of the group, this can go back in the past for compare it.
### CES 2020 (NukeSped)
###### The initial vector of the infection begin by a current exploit in HWP (CVE-2015-6585) to execute an EPS script, this download and execute the next stage of the infection.
![alt text](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/EPS.PNG)
###### This execute fisrtly a common trick RtlCaptureContext for have ability to register a top-level exception handler and avoid debbuging.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_anti-debug.png)
###### Once this done, the malware execute a series of actions like list the disks, process, files and push it in differents files as temp file in waiting to send the data to C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_sysinfo.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_disks.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_finfFile.png)
###### The backdoor push the cookie settings and guid for the identification in the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_pushguid.png)
###### This push the list of C2 address to contact, the languages to understand and begin the contact with the C2 in giving the host info. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_address.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_Options.png)
###### List of the languages used :
|RFC4646/ISO 639 Ref|Lang|
|:--:|:--:|
|Az-Arab|Azerbaijani in Arabic script|
|de-CH|Swiss German|
|en-US|English as used in the United States|

###### If the target is interesting for the group, this execute command and others tools in the computer infected.


## Cyber kill chain <a name="Cyber-kill-chain"></a>
###### The process graphs resume all the cyber kill chains used by the attacker. 
![alt text]()
## References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a>
###### List of all the references with MITRE ATT&CK Matrix

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |

## Indicators Of Compromise (IOC) <a name="IOC"></a>
###### List of all the Indicators Of Compromise (IOC)
|Indicator|Description|
| ------------- |:-------------:|

###### This can be exported as JSON format [Export in JSON]()	
## Links <a name="Links"></a>
###### Original tweet: 
* [https://twitter.com/RedDrip7/status/1186562944311517184](https://twitter.com/RedDrip7/status/1186562944311517184) <a name="Original-Tweet"></a>
* [https://twitter.com/Rmy_Reserve/status/1188235835956551680](https://twitter.com/Rmy_Reserve/status/1188235835956551680) 
* [https://twitter.com/a_tweeter_user/status/1188811977851887616](https://twitter.com/a_tweeter_user/status/1188811977851887616) 
* [https://twitter.com/spider_girl22/status/1187288313285079040](https://twitter.com/spider_girl22/status/1187288313285079040) 
* [https://twitter.com/objective_see/status/1187094701729443840](https://twitter.com/objective_see/status/1187094701729443840) 
###### Links Anyrun: <a name="Links-Anyrun"></a>
* [6850189bbf5191a76761ab20f7c630ef.xls](https://app.any.run/tasks/27ea35e6-6211-468d-9b8a-8c4cf22764ce)
* [JD-HAL-Manager.doc](https://app.any.run/tasks/42c972b1-ec38-4637-9354-9de930ff50b2)
* [public.dll](https://app.any.run/tasks/9eb78213-df55-44c3-9465-e58eb0869e58)
* [CES2020 참관단.hwp](https://app.any.run/tasks/31be34b3-4d72-4831-8b76-6dfebe729b84)
* [6850189bbf5191a76761ab20f7c630ef.xls](https://app.any.run/tasks/a766e70e-b07f-4a59-80fb-b18597d85b08)

###### External analysis: <a name="Analysis"></a>

* [Analysis of Powershell malware of Lazarus group](https://blog.alyac.co.kr/2388 )
* [Cryptocurrency businesses still being targeted by Lazarus](https://securelist.com/cryptocurrency-businesses-still-being-targeted-by-lazarus/90019/)

