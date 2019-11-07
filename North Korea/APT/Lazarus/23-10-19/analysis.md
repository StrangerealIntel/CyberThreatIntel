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
### CES 2020 incident (NukeSped)
###### We can see that the document target specifily the south korean exhibitors with the follow tittle "Application form for American Las Vegas CES 2020"
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/Doc.PNG)
###### This initial vector of the infection begin by a current exploit in HWP (CVE-2015-6585) to execute an EPS script, this download and execute the next stage of the infection.
![alt text](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/EPS.PNG)
###### This execute fisrtly a common trick RtlCaptureContext for have ability to register a top-level exception handler and avoid debbuging.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_anti-debug.png)
###### Once this done, the malware execute a series of actions like list the disks, process, files and push it in differents files as temp file in waiting to send the data to C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_sysinfo.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_disks.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_finfFile.png)
###### The RAT push the cookie settings and guid for the identification in the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_pushguid.png)
###### This push the list of C2 address to contact, the languages to understand and begin the contact with the C2 in giving the host info. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_address.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_Options.png)
###### List of the languages used :
|RFC4646/ISO 639 Ref|Lang|
|:-------------:|:-------------:|
|Az-Arab|Azerbaijani in Arabic script|
|de-CH|Swiss German|
|en-US|English as used in the United States|
###### Interesting to see that not only south korea language is choisen and show that the group target all exhibitors (more a hundred exhibitors only for South Korea). This think possibly that the group manage the event give hardware specifily for the shows to the customers, that explains why this to don't include specific language like South Korea. If the target is interesting for the group, this  can execute command and others tools in the computer infected.

###### We can see in the list of all the domains used that this all as different cloud providers and are legit website hijacked by vulnerable wordpress.
|IP|ASN|Organization|Route|City|Coordinates|Country|
|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|
|64.151.229.52|AS26753|In2net Network Inc.|64.151.192.0/18|Toronto|43.6861,-79.4025|Canada|
|185.136.207.217|AS203377|LAB internet ve Bilisim Hizmetleri|185.136.207.0/24|Eskiehir|39.7767,30.5206|Turkey|
|83.169.17.240|AS8972|Europe GmbH|83.169.16.0/21|Köln|50.9541,6.9103|Germany|
###### We can confirmed it by the Whois records and by the certificats push on the websites know at all the sites have between up early August 2019 at September 2019.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/HWP-cert.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/HWP-whois.png)
### HAL incident (JakyllHyde)
###### The document specifically target the Hindustan Aeronautics Limited company (HAL) that the national aeronautics in India. This use false announcements for recruitment for target probably interesting profile or internal employees in asking for their opinion about announcements.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_cover.png)
###### The attack vector is an maldoc which use a macro for drop and execute the implant. The first bloc is a declaration of function for load the future extracted dll.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_1.png)
###### The next bloc have multiple functions like decode from the base 64 in binary and string, verify the path of folder/file, create a folder and extract the correct payload from the form in maldoc according to the OS.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_2.png)
###### The following bloc have extraction functions (drop the lure) and for get the name of the lure and the dll.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_3.png)
###### We can see the autoopen function for execute the macro at the opening of the document and the data of the malware in base 64.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_4.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_5.png)
###### The backdoor begins to do the reconnaissance actions like list the process,system informations(Username, ComputerName ...)   
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_process.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_systeminfos.png)
###### After this list all the disks on the computer and all the files in current working directories in waiting the order of the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_disk.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_getinfos.png)
###### This have the possibility to intercepts keystrokes (push it in temporary file), make screenshots, send interesting files by stream of bytes data.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_keyboard.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_getscreenshot.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_getimage.png)
###### If the attacker wants this can push and remove the persistence performed by a Startup key.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_writeKey.PNG)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_pushpersistence.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_deletekey.png)
###### The backdoor contact the following IP :
|IP|ASN|Organization|Route|City|Coordinates|Country|
|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|
|193.70.64.163|AS16276|thetiscloud.it|193.70.0.0/17| San Donato Milanese|45.4105,9.2684|Italy|
###### By the certificates, we can see that the website is up since 2018, seems be a legit website hijacked.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/MAL-Cert.png)
###### Like the last incident, Lazarus group try to get high technologies, this possible that the interest is the fact that HAL is in cooperation for product and use the new french militairy aircraft (Rafale) in the India country.

### OSX Malwares (OSX.Yort)



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
###### Ressources :
* [List of South Korea exhibitors in CES2020](https://www.ces.tech/Show-Floor/Exhibitor-Directory.aspx?searchTerm=&sortBy=country&filter=South%20Korea)
