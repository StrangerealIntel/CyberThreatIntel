# APT-C-37 campaign in the Middle East
## Table of Contents
* [Malware analysis](#Malware-analysis)
  + [Initial vector](#Initial-vector)
  + [Loader](#loader)
  + [VB Backdoor](#Backdoor)
* [Cyber Threat Intel](#Cyber-Threat-Intel)
  + [Origin of the method for the JS Backdoor](#Origin)
  + [APT-C-37 Campaign](#APT)
  + [A army in perdition, an difficult situation](#Army)
  + [A war of misinformation](#War)
  + [The drone attack, a result of the information campaign ?](#Result)
  + [Finally ?](#Finally)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Documents](#Documents)

## Malware analysis <a name="Malware-analysis"></a>
### Initial vector <a name="Initial-vector"></a>
###### The initial vector use an SFX executable, who drop a lnk file for the persistence, a vbs file and the docx file for decoys the victim. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/strings.png "")
###### We can note that the topic of the document only for decoy the victims is about a scandal in the Hamas leaders.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/content.png "")
###### Here the translation in english of the content of the document.
###### A new scandal for a Hamas leader <br> In the difficult circumstances of our people in the Gaza Strip, and what the head of the family suffers in order to earn a living, but financial and moral corruption does not end in this stray rogue in the name of religion. <br> We received leaked news that RA, a Hamas leader in the northern Gaza Strip, was interrogated on charges of financial embezzlement. Investigations show that he has an affair with a girl. As the private source said to us, he was stopped from practicing any political or movement activity after this incident. <br> Question how long ????????????????? <br> For more details please email us at the following email. <br> palemptn@yahoo[.]com
###### We can note too that the email address is valid and invite to send a mail about this event.
###### We can also note the multiples possibilities for push the persistence and options.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/lnkfile.png "")
###### This execute the vbs file for push the persistence in the startup menu, hide it in changing these attributes and launch the persistence (lnk file)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/VBScode.png "")
###### This download the VB script and execute it by mshta call.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/lnk.PNG "")
###### On the VB code, we can observed that use BITS functionality for download by a job the JS script to execute on the victim. Secondly, this checks the architecture of the system and executes the correct path of wscript and push the windows out the screen.
### Loader <a name="loader"></a>
###### We can see that use function for decode the commands with an array of bytes.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/encodeJS.png "")
###### For decode the string, we use the next function used by the backdoor for decode the commands.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/decodeJS.png "")
###### You can now change the encoded commands.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/decStr.png "")
###### Once the encoded strings removed, we have the following code :
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/lay1dec.png "")
###### As anti-forensic method, a method which can know if determiner if a debugger is present.
 ![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/zoomdebug.PNG "")	
###### Finally, we can observe a Wscript execution with a function splter which split for getting an array of bytes, convert to ASCII and after execute the script with execute call.
###### By the following PowerShell script, we can get the second layer that is the VB Backdoor.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/declayer.png "")	
### VB Backdoor <a name="Backdoor"></a>
###### Firstly, the script get the system informations about the system of the victim and send to one the list of C2 in the logical sense (not random call on the list of C2) with the suffix "/is-ready". The backdoor uses a while loop for rest in communication with C2 by sending a pulse with the system information of the victim.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/FirstAnal.png "")	
###### This send the data with the following structure to the C2 (Here from the Anyrun sandbox) :
`C4BA3647<|>USER-PC<|>admin<|>Microsoft Windows 7 Professional <|>plus<|>nan-av<|>` 
###### We can note that the USB spread option isn't used on this sample. The structure of the reply to the C2 is the next :
`[volumeserialnumber]<|>[computername]<|>[username]<|>plus<|>[AV product (yes -> name or no ->nan-av)]<|>[usbspreading option (= "")]<|>`
###### In a second time, when a response of the C2 was given and use a switch structure for execute the command.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/secAnal.png "")
###### Now, we analyse all functions used by this switch. As first function, we can see a function used by others functions of the script and used for sending the data to the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/postfunc.PNG "")
###### We can observe after a group of functions who use the WQL queries by the WMI for getting the system informations, this is used by the attacker as profiling the victim.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/infofunc.PNG "")
###### After, a function is used by the attacker for download an executable file.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/downfunc.PNG "")
###### In the same idea for the attacker, a function which give the possibility to read the bytes of files in a buffer and send it to the C2 is present.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/upfunc.PNG "")
###### The next function give to the attacker to have the list drives on the computer.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/listdrivesfunc.PNG "")
###### Another function can enumerate the paths of folders, files and to give in more the attributes of them.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/dirfunc.PNG "")
###### And third function is used for getting the list of the process running in the computer.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/processfunc.PNG "")
###### The last function exit the process with a kill signal by taskkill call.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/exitfunc.PNG "")

###### We can resume the list of commands of the backdoor :
|Command|Description|
| :---------------: |:-------------|
|execute| execute a command DOS/Powershell|
|send|Download a file to execute|
|site-send|Function don't exist but have the same arg that send command, seems be an edited function of site-send and not deleted ?|
|recv|Read a file, put in a buffer and send to the C2|
|enum-driver|Send the list of drives to the C2|
|enum-faf|Get list of the folders, files and attributes and send it to the C2|
|enum-process|Get list of the process (name, id, path of the executable) and send it on the C2|
|delete|Function don't exist but by the params seems give to the attacker to delete folders or files|
|exit-process|Kill the backdoor process but can't remove the persistence, an "execute" command must be performed before for delete it in the registry|

###### All the IP are hosted on differents cloud provider.
|IP|Route|ASN|Organization|Country|City|Region|Coordinates|
|:---------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|
|66.154.103.156|66.154.102.0/23|AS8100|QuadraNet Enterprises LLC|United States|Secaucus|New Jersey| 40.7895,-74.0565|
|37.48.111.5|37.48.64.0/18|AS60781|LeaseWeb Netherlands B.V.|Netherlands|Noord-Holland|Amsterdam|52.3824,4.8995|
|85.17.26.65|85.17.0.0/16|AS60781|LeaseWeb Netherlands B.V.|Netherlands|Noord-Holland|Amsterdam|52.3824,4.8995|

## Cyber kill chain <a name="Cyber-kill-chain"></a>
###### The process graph resume the cyber kill chain used by the attacker.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/cyber.PNG "")

## Cyber Threat Intel <a name="Cyber-Threat-Intel"></a>
### Origin of the method for the JS Backdoor <a name="Origin"></a>
###### Firstly, the method for load the JS Backdoor is edited from a post published in 2015 on a forum for show a method for the both architecture for the development of a worm.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/Post.PNG "")
###### We can see that the name of the instance is changed and the html tags are removed. If we add the notes from the malware analysis, we can conclude that the malware has been edited in emergency.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/matchcode.PNG "")

### APT-C-37 Campaign <a name="APT"></a>
###### In March 2019, a new campaign analysed by 360 Core Security in March 2019 of APT-C-37 show the analysis of the H-worm.We can note that as obfuscation is based on the utilisation of the functions Mid for extract the characters and some replace for change the characters for getting the script to execute. We can note too that the level of complexity of the obfuscation is very low and can be easily analysed and detected.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/geZ6pXr1.png "")
###### In the same forum, we can found on a mega link the source code of the VB RAT Fkn0wned in April 2018 used by the same campaign on of the APT. With the code of H-worm like the analysis of 2013, we can show that APT-C-37 have probably get the resources from this forum for launches their operations.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/codeRAT.png "")
##### The recent sample of H-worm have many removed and edited functions compared at the original version like remove the persistence, the function Sleep ...
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/oIdfwmrN.png "")
###### On the IOC, we can recognize the structure used by the H-worm with "is-ready".
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/fnVYrkD1.png "")
###### The goals of this campaign and since the detection in 2015 is to use RAT for android and windows systems for spying. The last operation attacks Amaq media and Al Swarm News Agency websites which are used for the propaganda of ISIS (Salafism). The group have used a group of words for pick, the interest of the victims, for example, the app is named "زوجات الرسول" (in english "The Wives of the Prophet").

###### In addition of this and the date of submission, this sample has been used in a campaign of profiling. In the submissions, we can observe some samples matching this own sample.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/parents.png "")
###### The informations of the sandbox show the similarities in the structure of the URL and C2 and the aba, dyndns domains.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/infolast.png "")
###### This sample spotted early August use the same TTPs, IPs and domains used, this again an edited version of H-worm who is used. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/spotted.png "")
###### The document is a decoy too and talk about a new investigation on an incident in the Gaza Strip.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/contentold.png "")
###### Here the translation in english of the content of the document.
###### In the name of of Allah the Merciful<br>And don't take account of God, oblivious to what the oppressors do, but delays them for a day in which you see the vision.<br>A statement issued by the sons of the martyr, God willing "Mohamed Ali Abdel Qader Radwan"<br>We, the sons of the martyr Mohammed Ali Abdel Qader Radwan, were surprised as everyone was surprised in the Gaza Strip; the news abuzz with social media networks;<br>A representative of the family of martyr Mohammed Ali Abdel Qader Radwan, who was martyred in the invasion of Beirut on 03.11.1984<br>Accordingly, we are the sons of the martyr condemn and condemn this act, which is tantamount to rape our right to pilgrimage, and we believe that the decision of Dr. Anas for Hajj travel is invalid and fraud and fading.<br>Especially since the declared justification for the press today that the martyr's sons have given their nephew the right to do Hajj is not true, and he has nothing to do with the truth.<br>No one has entrusted Anas to travel on his behalf, and there is no official authorization or waiver from the martyr's sons, especially Anas; Outside the Gaza Strip.<br>Accordingly, we are martyrs' family.<br>Regretting the situation reached by some .. We call on the Foundation for the Care of the Families of the Martyrs and the Wounded represented by its President His Excellency Minister / Intisar Minister to instruct and give the order to investigate the incident the subject of the statement and our fairness.<br>We also call on the Ministry of Awqaf and Hamas to reconsider the following:<br>Dr.Ismail Said Radwan.<br>Dr. Anas Ismail Radwan.<br>They take the platforms and teach people religion.<br>About the sons of the martyr<br>Legal Advisor / Ibrahim Mohamed Ali Radwan.

###### Dr. Ismail Said Radwan is a Hamas leader and Minister of Awqaf and Religious Affairs in the Hamas government headed by Ismail Haniyeh, who controls Gaza. He previously served as Hamas' media spokesman, and is the chairman of the Al - Aqsa Media Network.Anas Radwan is son of Hamas' senior official Ismail Radwan.

###### We can note that at this time, this target now Hamas and in the same way of using non-existent events with keywords already used by this group ("Martyrs", "investigate", "incident", "religion", "decision", "justification").

###### On the matching YARA rule, we can conclude that the campaign since at least May 2019.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/rule.png "")

###### The fact that the month is May is interesting. The 3 May 2019, after two Israeli soldiers were injured by sniper fire in the Gaza Strip during the weekly protests at the Gaza–Israel border. In response, the Israeli Air Force carried out an airstrike an Hamas post, killing two Palestinians that have provoke the military response by a hundred rockets. On 5 May 2019, Israel by the help of the Unit 8200 of Military Intelligence (have done Stuxnet and Duqu) have suspected Hamas cyber-attack and reply by immediate air strike (this rest still suspected, no report analyzing the exploiting tools, technologies and objectives targeted).

### A army in perdition, an difficult situation <a name="Army"></a>
###### Since the last decade, the inexperience of the army on military issues, rigid doctrine, misunderstanding of the adversary, over-reliance on air and all-technological operations, loss of skills in the IDF, hesitations of unit commanders, the belief - erroneous - that the Israeli population would not accept the possible losses, a reorganized but deficient logistics, the non-mastery of communication. If we add the Syria situation and the result of the confrontation in 2006 who have add new enemies against Israel, this creates a difficult situation for these leaders.
###### We can recall the manifestations against Netanyahu immunity between February at May 2019 who have weakened the popularity rating. Recently, during the election period, each action or precious opportunity can be used for that purpose or to develop a doctrine such as the creation of housing in the colonies.

### A war of misinformation <a name="War"></a>
###### Like all recent conflicts, communication networks are used to send false news and propaganda or to create it because people can not understand the situation. For example, recently, we could hear that a false evacuation of wounded was launched against Hezbollah for pushing to stop firing, but that is to ignore, guerrilla warfare and the outcome of recent conflicts where it isn't about rockets that destroyed military equipment, but Israeli forces that sabotaged their own equipment by the fear of new recruits and lack of experience. In the same vein, fear of rocket fire on a city can't be realistic, Hezbollah given the priority to garrisons of the border army, infrastructure that a better choice due this have the capacities to destroying the guerilla, this argument is only valid in Israel to prepare the people for the possibilities of declaring war.

###### In this way, some images were sent in both sides to use this factor as propaganda vector. For example, an image taken with a drone from the netanyahu window was published on social media at for purposes of spreading retaliatory capabilities. If we see the picture with the naked eye, we can see that the shadow of the drone is not indicated in the wall inside the room, the facade is a decoration, false coordinates and the blur apply to the entire photo.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/c654ede55e275431042d32334f8cfd3a5526cb72.196671-600.png "")
###### With the ELA algorithm, we can see the last modifications on the pictures. In using this it, we can see all the precedents elements are added at the original picture (probably a meeting with members of government).
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/c654ede55e275431042d32334f8cfd3a5526cb72.196671-ela.png "")
###### In same time, other pictures are released about decoy targets, with the ELA algorithm, we can see that the multiple compressions by the algorithms, the picture is very dark and the pictures are only modify for writing the indicators of interest.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/EDOYGiAXsAEA4Kq.jpg%20large.jpg "")
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/aa18205de56e2cbe15471c3cc1530e587ab975a0.35923-ela-600.png "")
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/EDOYGWjWsAAsfM1.jpg%20large.jpg "")
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/Images/3fb1c19ecfe9c11d779b8dae397cd781b64c56ef.21349-ela.png "")
###### Recently, in the same way for develop the feeling of fear, Israel government have claimed that Iran build precision missiles, this rest to prove it but the scheme of reflexion is the same, a war of fear and misinformation.

### The drone attack, a result of the information campaign ? <a name="Result"></a>
###### We have got confirmation that the drones used for the operation are trapped with explosives for explode at the moment that the enemies recovers it, that indicate that the Israel know that in these regions the enemies is present and valuable targets can be attainable. In the comparing with the past, we can note that probably some operations of spying are active as survey by the fact of the ideology of "no injury" and use all the aims for avoid victims on the Israeli forces or civilians.

### Finally ?<a name="Finally"></a>
###### The APT-C-37 TTPs and methods of decoys the victim match. We can show the great increase on the capacity to obfuscate and operational capabilities. The reason of spying precisely the Muslim armies rest unknown and the matching with the events between Israel and the Hamas and Hezbollah is very troubled. The objectives and the organization rest very blurred but this rest possible that the group can be manipulating by countries or group of people for their own objectives.
## References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a>
###### List of all the references with MITRE ATT&CK Matrix

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|T1170 - Mshta<br>T1064 - Scripting|https://attack.mitre.org/techniques/T1170<br>https://attack.mitre.org/techniques/T1064|
|Persistence|T1197 - BITS Jobs<br>T1060 - Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1197<br>https://attack.mitre.org/techniques/T1060|
|Defense Evasion|T1197 - BITS Jobs<br>T1170 - Mshta<br>T1064 - Scripting|https://attack.mitre.org/techniques/T1197<br>https://attack.mitre.org/techniques/T1170<br>https://attack.mitre.org/techniques/T1064|
|Discovery|T1012 - Query Registry|https://attack.mitre.org/techniques/T1012|
|Lateral Movement|T1105 - Remote File Copy|https://attack.mitre.org/techniques/T1105|
|C2|T1105 - Remote File Copy|https://attack.mitre.org/techniques/T1105|

## Indicators Of Compromise (IOC) <a name="IOC"></a>

###### List of all the Indicators Of Compromise (IOC)

| Indicator     | Description|
| ------------- |:-------------:|
|فضيحة جديدة لأحد قيادات حماس.exe|03d82852bbb28d1740e50206e7726c006b9b984a8309e2f203e65a67d7d3bcad|
|History.lnk|3853e0bf00d6dbfc574bc0564f0c90b93a66d644dd4dc8b8c00564f0b6edf581|
|ss.vbs|2e5f9bb1cef985eab15ad8d9072e51c71be2810fea789836b401b96bc898943b|
|news.docx|08fa35e25f4c7a6279a84b337d541989498d74f2c5e84cc4039d667fedc725c7|
|xyx.jse|32e216942f995f285947c7e7ee8cf438440c8a1e033bb27517f5e5361dafa8e8|
|adamnews.for.ug|Domain requested|
|israanews.zz.com.ve|Domain requested|
|mmksba.dyndns.org|Domain C2|
|webhoptest.webhop.info|Domain C2|
|mmksba.simple-url.com|Domain C2|
|85.17.26.65|IP requested|
|66.154.103.156|IP C2|
|37.48.111.5|IP C2|
|http[:]//israanews.zz.com.ve/hw.zip.zip|HTTP/HTTPS requests|
|http[:]//adamnews.for.ug/hwdownhww|HTTP/HTTPS requests|
|http[:]//webhoptest.webhop.info:4433/is-ready|HTTP/HTTPS requests|
|http[:]//mmksba.simple-url.com:4422/is-ready|HTTP/HTTPS requests|
|http[:]//mmksba.dyndns.org:4455/is-ready|HTTP/HTTPS requests|
|http[:]//webhoptest.webhop.info:4433/is-sending|HTTP/HTTPS requests|
|http[:]//mmksba.simple-url.com:4422/is-sending|HTTP/HTTPS requests|
|http[:]//mmksba.dyndns.org:4455/is-sending|HTTP/HTTPS requests|
|http[:]//webhoptest.webhop.info:4433/is-recving|HTTP/HTTPS requests|
|http[:]//mmksba.simple-url.com:4422/is-recving|HTTP/HTTPS requests|
|http[:]//mmksba.dyndns.org:4455/is-recving|HTTP/HTTPS requests|
|http[:]//webhoptest.webhop.info:4433/is-enum-driver|HTTP/HTTPS requests|
|http[:]//mmksba.simple-url.com:4422/is-enum-driver|HTTP/HTTPS requests|
|http[:]//mmksba.dyndns.org:4455/is-enum-driver|HTTP/HTTPS requests|
|http[:]//webhoptest.webhop.info:4433/is-enum-faf|HTTP/HTTPS requests|
|http[:]//mmksba.simple-url.com:4422/is-enum-faf|HTTP/HTTPS requests|
|http[:]//mmksba.dyndns.org:4455/is-enum-faf|HTTP/HTTPS requests|
|http[:]//webhoptest.webhop.info:4433/is-enum-process|HTTP/HTTPS requests|
|http[:]//mmksba.simple-url.com:4422/is-enum-process|HTTP/HTTPS requests|
|http[:]//mmksba.dyndns.org:4455/is-enum-process|HTTP/HTTPS requests|

###### This can be exported as JSON format [Export in JSON](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Unknown/APT-C-37/26-08-19/IOC_APT-C-37_04-09-19.json)	

## Links <a name="Links"></a>
###### Original tweet: [https://twitter.com/Timele9527/status/1166188375109296128](https://twitter.com/Timele9527/status/1166188375109296128) <a name="Original-Tweet"></a>
###### Links Anyrun: <a name="Links-Anyrun"></a>
* [فضيحة جديدة لأحد قيادات حماس.zip (A new scandal of one of the leaders of Hamas.zip)](https://app.any.run/tasks/59ed8062-cf77-4d73-81bd-19cb26b7c7c6)
* [xyx.jse](https://app.any.run/tasks/baa4f59c-969b-4617-b926-2d41da5e18b0)
* [7d989a9a3faef377f2556e090014f96ba3bf8a8299ba256d30fab41710499a7c](https://app.any.run/tasks/db144694-cd40-4697-ab47-d9179ad0932e)
###### Documents: <a name="Documents"></a>
* [Evaluating ELA](http://fotoforensics.com/tutorial-ela.php)
* [Analysis of APT-C-37](http://blogs.360.cn/post/analysis-of-apt-c-37.html)
* [Now You See Me - H-worm by Houdini](https://www.fireeye.com/blog/threat-research/2013/09/now-you-see-me-h-worm-by-houdini.html)
* [Pulse alienvault about IP C2 in March 2019](https://otx.alienvault.com/indicator/ip/66.85.157.86)

