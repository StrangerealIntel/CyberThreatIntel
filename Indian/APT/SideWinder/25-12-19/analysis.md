# SideWinder same targets, same TTPs, time to counter-attack ! 
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
<h6>The initial vector is an RTF file who use an well-know vulnerability (CVE-2017-11882) for execute a js script (1.a) form the package of OLE objects. </h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/25-12-19/Pictures/RTF_objects.PNG">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/25-12-19/Pictures/obj1.PNG">
</p>
<h6>We can observe on the code of the exploit that jump and rebuild the command to execute. </h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/25-12-19/Pictures/obj2.PNG">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/25-12-19/Pictures/exploit.png">
</p>
<h6>As first, we can observe that a series of functions are used for obfuscate the criticals parts of the script.</h6>
```javascript
		var OaXQT = ActiveXObject;
		var cRKGlc = String.fromCharCode;
		function RDDb(str) 
    {
			var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXY"+"Zabcdefghijklmnopqrstuvwxyz0123456789+/="
			var b, result = "", r1, r2, i = 0;
			for (; i < str.length;) 
      {
				b = b64.indexOf(str.charAt(i++)) << 18 | b64.indexOf(str.charAt(i++)) << 12 |
					(r1 = b64.indexOf(str.charAt(i++))) << 6 | (r2 = b64.indexOf(str.charAt(i++)));
				result += r1 === 64 ? cRKGlc(b >> 16 & 255) :
					r2 === 64 ? cRKGlc(b >> 16 & 255, b >> 8 & 255) :
					cRKGlc(b >> 16 & 255, b >> 8 & 255, b & 255);
		  }
			return result;
		};
		function SJnEuQM (key, bytes){
			var res = [];
			for (var i = 0; i < bytes.length; ) {
				for (var j = 0; j < key.length; j++) {
					res.push(cRKGlc((bytes.charCodeAt(i)) ^ key.charCodeAt(j)));
					i++;
					if (i >= bytes.length) {
						j = key.length;
					}
				}
			}
			return res.join("")
			}
		function EvpTXkLe(bsix){
		return SJnEuQM(keeee,RDDb(bsix))
		}
		var keeee = SJnEuQM("YjfT",RDDb("altWY2"+"hcV2xq"+"XA=="));
```

<h2>Threat Intelligence</h2><a name="Intel"></a></h2>
<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>The process graph resume cyber kill chains used by the attacker :</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/25-12-19/Pictures/Cyber.png">
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
|Execution|Execution through Module Load<br>Exploitation for Client Execution|https://attack.mitre.org/techniques/T1129/<br>https://attack.mitre.org/techniques/T1203/|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060/|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/|

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/JSON/MITRE_ref.json">Export in JSON</a></h6>
<h2>Yara Rules<a name="Yara"></a></h2>
<h6> A list of YARA Rule is available <a href="">here</a></h6>
<h2>Knowledge Graph<a name="Knowledge"></a></h2><a name="Know"></a>
<h6>The following diagram shows the relationships of the techniques used by the groups and their corresponding malware:</h6>
<p align="center">
  <img src="">
</p>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/RedDrip7/status/1206898954383740929](https://twitter.com/RedDrip7/status/1206898954383740929) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [Policy on Embedded Systems.doc](https://app.any.run/tasks/1fac2867-012c-4298-af36-a4810d9b72db)
* [adsfa.rtf](https://app.any.run/tasks/72ec8c7c-5542-48fe-8400-ba840de9c0bd)
* [out.rtf](https://app.any.run/tasks/34c8345c-b661-4ca5-ba15-58dcc4e6d968)

<h6> Resources : </h6><a name="Ressources"></a>

* [The SideWinder campaign continue](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/11-10-2019/Analysis.md)
* [CVE-2017-11882](https://github.com/embedi/CVE-2017-11882)dz
