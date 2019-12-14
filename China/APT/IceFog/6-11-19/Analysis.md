# APT Icefog target Hanoi ?
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
<h6>The initial vector</h6>
<p align="center">
  <img src="">
</p>
<h2>Threat Intelligence</h2><a name="Intel"></a></h2>
<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>The process graph resume cyber kill chains used by the attacker :</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/China/APT/IceFog/6-11-19/Pictures/Cyber.PNG">
</p>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> List of all the Indicators Of Compromise (IOC)</h6>

|Indicator|Description|
| ------------- |:-------------:|
|||
<h6> The IOC can be exported in <a href="">JSON</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Rundll32<br>Execution through Module Load<br>User Execution|https://attack.mitre.org/techniques/T1085/<br>https://attack.mitre.org/techniques/T1129/<br>https://attack.mitre.org/techniques/T1204/|
|Persistence|Office Application Startup|https://attack.mitre.org/techniques/T1137/|
|Defense Evasion|Rundll32|https://attack.mitre.org/techniques/T1085/|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/|

<h6> This can be exported as JSON format <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/China/APT/IceFog/6-11-19/JSON/Mitre_TTPs.json">Export in JSON</a></h6>
<h2>Yara Rules<a name="Yara"></a></h2>
<h6> A list of YARA Rule is available <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/China/APT/IceFog/6-11-19/Yara_Rule_IceFog_Nov19.yar">here</a></h6>
<h2>Knowledge Graph<a name="Knowledge"></a></h2><a name="Know"></a>
<h6>The following diagram shows the relationships of the techniques used by the groups and their corresponding malware:</h6>
<p align="center">
  <img src="">
</p>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/securitydoggo/status/1192073306255560704](https://twitter.com/securitydoggo/status/1192073306255560704) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [tai lieu tong quan bien gioi viet-lao_pub_thonghnt.rtf](https://app.any.run/tasks/8ccde475-27a1-402a-a0c3-631998ccd120)
* [adcache.dll](https://app.any.run/tasks/53b5d3eb-dd8b-4e51-b64b-793cd2b0e190)

<h6> Resources : </h6><a name="Ressources"></a>

* [C2 list and kill switch](https://twitter.com/vupt_bka/status/1192342494240899072)
* [Ancient ICEFOG APT malware spotted again in new wave of attacks](https://www.zdnet.com/article/ancient-icefog-apt-malware-spotted-again-in-new-wave-of-attacks/)
