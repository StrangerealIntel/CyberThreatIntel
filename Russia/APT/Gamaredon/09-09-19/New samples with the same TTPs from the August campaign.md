# New samples with the same TTPs from the August campaign
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber Threat Intel](#Cyber-Threat-Intel)
* [Indicators Of Compromise (IOC)](#IOC)
* [Links](#Links)
  + [Originals Tweets](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Documents](#Documents)
## Malware analysis <a name="Malware-analysis"></a>
###### The first two samples are maldocs use the CVE-2017-0199 for call a remote template to get the second stage but isn't available.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/APT/Gamaredon/09-09-19/Images/Remote.png "")
###### The last sample is an SFX archive who drop and execute an cmd file.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/APT/Gamaredon/09-09-19/Images/cmdfile.png "")
###### This drops a vbs file and powershell file and execute the vbs file who create a persistence and execute the powershell script for sending the GUID and the username to the C2. If the target is interesting, the attacker pushes the executable to execute on the victim with a URL with the GUID.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/APT/Gamaredon/09-09-19/Images/vbsfile.png "")
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/APT/Gamaredon/09-09-19/Images/ps1file.png "")

## Cyber Threat Intel <a name="Cyber-Threat-Intel"></a>
###### The content of the first is based on the event of Ukrainian-Romanian military exercise:
###### MINUTES OF THE OPERATIONAL MEETING WITH THE GUIDELINES OF THE SHIPPING OF KHVP GUNP IN THE KHERSON REGION<br>September 05, 2019, Kherson<br>Chairman - Chief of the Ship Enterprise Salmanov SV<br>Secretary - Degtyar IM<br>Present: Rogozhin OV, Stefanyuk MP, Churilov DV, Chernov AV, Chernenko RY, the personnel of the Ship VP.<br>Agenda:<br>1. On the organization and implementation of operational and preventive testing to counteract the criminal offense in the field of gambling business in the territory of service of the Shipwreck of the KHP GUNP in Kherson region.<br>HEARD:<br>1. Information the chief of SKP of the Ship VP KHVP GUNP in the Kherson area of ​​the major of police MP Stefanyuk «On the organization and carrying out of operative and preventive testing in the field of counteraction to criminal offense in the sphere of gambling in the territory of the Ship district of Kherson».<br>SUBMITTED BY:<br>Salmanov SV, Rogozhin OV, Stefanyuk MP, Churilov DV, Chernov AV, Salmanov SV<br>APPROVED:<br>1. To recognize the work of the Ship Enterprise of the KVP of the SUNP in organizing and conducting operational and preventive testing in the field of counteraction to the criminal offense in the sphere of gambling that does not fully meet the requirements of the SUNP:<br>2. To the deputy chief (OV Rogozhin) to determine the main ways of overcoming problems concerning the organization and carrying out of operative-preventive testing on counteraction to the criminal offense in the sphere of gambling in the service territory.<br>3. Acting the chief of SKP of the Ship VP (Stefanyuk MP):<br>3.1. Aim for a silent apparatus to provide information regarding the detection of illegal installation and use of gaming equipment in the service area.<br>3.2. Work out shops, premises where rental of gaming equipment is possible.<br>3.3. Conduct an analysis of available operational information on activities in the Ship Area of ​​gambling facilities<br>3.4. To carry out a complex of measures for prevention and termination of illegal gambling business in the territory of the Ship district of Kherson.<br>3.5. Conduct inspections on compliance with the requirements of the Law of Ukraine "On Prohibition of Gambling in Ukraine", involving relevant executive authorities, mass media and public organizations.<br>3.6. To conduct a complex on the detection of facts of illegal installation and use of gaming equipment, carrying out illegal activities in a veiled form with the use of various social and everyday objects and modern means in the sphere of high technologies.<br>3.7. Collect materials in accordance with the Guidelines for Identification, Documentation, Investigation of Crimes Related to the Provision of Gambling Services.<br>3.8 Take steps to document illegal activities and to prosecute illegal organizers and owners of illegal business related to the provision of gambling services.<br>4.The head of the JV of the Ship VP (Churilov DV):<br>4.1. Ensure timely entry in the Unified Register of pre-trial investigations of information about the facts of the gambling business discovered during the working out.<br>4.2. Ensure proper organization of pre-trial investigation, as well as prompt support of criminal proceedings, providing for the necessary set of procedural actions in accordance with the requirements of the Criminal Procedure Code of Ukraine.<br>4.3. Provide necessary necessary unspoken investigative (search) actions to document illegal activities of gambling business organizers.<br>4.4. Organize proper interaction between operational services, investigation units, prosecutors' offices and local courts for timely approval and obtaining sanctions for searches, imposition of administrative fines in accordance with Art. 181 of the Code of Administrative Offenses of Ukraine, as well as taking procedural decisions on revealed facts of violation of the requirements of the Law of Ukraine "On Prohibition of Gambling in Ukraine".<br>5. Deputy Head of the VP (Rogozhin OV)<br>5.1. Provide task forces with transportation, facilities for processing inspection materials, and necessary supplies.<br>5.2. In order to properly retain the seized gaming equipment, prepare suitable premises within the police department, which should be under 24/7 police protection.<br>6. Control over the implementation of the decision of the operational meeting to place on the Deputy Chief of the Ship VP FVP Major of Police Rogozhin OV<br>Head of meeting:<br>police colonel SV O. Salmanov
###### The second sample is fragmented and can't show the content.
###### And the last content is linked with another sample analysed on my last analysis of Gamaredon campaign. 
###### Lugansk District Administrative Court<br>For Judge TI Chernyavskaya<br>Case No. 360/1807/19<br>93411, Severodonetsk, Luhansk region, prospectus of Cosmonauts, 18.<br>On your decision to open proceedings in the administrative case of 02.08.2019 in the case № 360/1807/19 on the statement of claim of the lawyer Sutkova Rena Agabekovna in the interests of Chizhik Konstantin Vladimirovich to the Ministry of Defense of Ukraine on the recognition of illegal and the cancellation of the decision and the obligation to make certain ,<br>I would like to inform that citizen Chizhik Konstantin Vladimirovich on May 4, 2017 by the original number VSZ-237 / OGD-46 was sent a simple letter by letter to the Lugansk regional military commissariat (hereinafter - Lugansk DEC), by the citizen K. Chyzhik, according to from the Minutes of the meeting of the Commission of the Ministry of Defense of Ukraine on consideration of issues related to the appointment and payment of one-time financial assistance and compensation amounts No. 38 of April 14, 2017, citizen K. Chyzhik was denied the appointment of one-time financial assistance services are due even in connection with the establishment of disability under 3 stay in the country, where people were fighting because not filed a document indicating that the circumstances of injury.<br>Proof of sending this letter to K. Chizhik's citizen is the entry in the register of sending simple correspondence for 2017 under No. 469, which was filed in case 314 / pc (Register for sending and receiving correspondence) of the Luhansk DEC.<br>Evidence of delivery to the citizen K. Chizhik of the letter of the Luhansk Oblast Military Commissariat dated 04.05.2017 № VSZ-237 / OGD-46 with a copy of the minutes of the meeting of the Ministry of Defense of Ukraine on consideration of issues related to the appointment and payment of one-time financial aid and compensation amounts April 2017, number 38, there is no Lugansk DEC.<br>Appendix: duly certified copy of the register of sending simple correspondence to Lugansk DEC for 2017, where number 469 means sending correspondence to Chizhik KV. No. VSZ-237 / OGD-46 on 3 sheets, to the addressee only.<br>Military Commissioner<br>Lugansk Regional Military Commissariat<br>Colonel Y. POLULYASHCHENKO<br>Sergey Lukin, (06452) 4-04-08
###### The C2 used by the maldoc is the same like another sample analysed early August.
## Indicators Of Compromise (IOC) <a name="IOC"></a>

###### List of all the Indicators Of Compromise (IOC)

| Indicator     | Description|
| ------------- |:-------------:|
|протокол.docx|9a1384868090f54630bc8615c52525a26405a208da1857facb7297d66c69b5c1|
|18f4aebeac09bd57cf90452facf456a4c6b56dd53a79d08eb5a1d20435acaca6.exe|18f4aebeac09bd57cf90452facf456a4c6b56dd53a79d08eb5a1d20435acaca6|
|481eee236eadf6c947857820d3af5a397caeb8c45791f0bbdd8a21f080786e75.docx|481eee236eadf6c947857820d3af5a397caeb8c45791f0bbdd8a21f080786e75|
|http[:]//libre-templates.ddns.net/internet.dot|HTTP/HTTPS requests|
|http[:]//libre-templates.ddns.net/|HTTP/HTTPS requests|
|list-sert.ddns.net|Domain requested|
|libre-templates.ddns.net|Domain requested|
|141.8.192.153|IP requested|

###### This can be exported as JSON format [Export in JSON](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Russia/APT/Gamaredon/09-09-19/IOC_Gamaredon_09-09-19.json)	

## Links <a name="Links"></a>
###### Originals tweets: 
* [https://twitter.com/spider_girl22/status/1169830999837986819](https://twitter.com/spider_girl22/status/1169830999837986819) <a name="Original-Tweet"></a>
* [https://twitter.com/Papyshev/status/1169609890593198080](https://twitter.com/Papyshev/status/1169609890593198080)
###### Links Anyrun: <a name="Links-Anyrun"></a>
* [протокол.docx](https://app.any.run/tasks/99305ee6-3b20-4950-ab29-9dc44a18b380)
* [18f4aebeac09bd57cf90452facf456a4c6b56dd53a79d08eb5a1d20435acaca6.exe](https://app.any.run/tasks/31b1bef7-948e-4813-9445-b22ef3ab3837)
* [481eee236eadf6c947857820d3af5a397caeb8c45791f0bbdd8a21f080786e75.docx](https://app.any.run/tasks/a7eab6e6-b57f-4892-9607-c615a940bf6b)
###### Old sample:
* [96f9f7a5c6a7452f385727708c69bf158e2d9461ad1bc683ba9082306b210e0e.docx](https://app.any.run/tasks/0cb08909-3b77-45f2-af72-fa703cc90fe0)
###### Ref previous analysis: [Gamaradon sample analysis 16-08-19](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Russia/APT/Gamaredon/16-08-19/Malware%20analysis%2016-08-19.md)
###### Documents: <a name="Documents"></a>
* [Ukrainian-Romanian Riverine-2019 military exercise starts on Danube](https://www.unian.info/society/10673661-ukrainian-romanian-riverine-2019-military-exercise-starts-on-danube.html)
