## Peace comeback, maldocs comeback
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Yara rules](#Yara)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [References](#References)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector of the infection is an NSIS executable, this content the pdf (lure) and the dll (MoriAgent).This initialize the OLE object used for the extraction and execution of the dropped object, this defines the current directory on the Temp directory.</h6>

<center><img src ="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/NSIS/entry0.png"></img></center>

<h6>Once initialized, the OLE initializes the process of extracting and executing the two objects in the archive.This uses the switch structure of the NSIS executable for execute the commands, once the files extracted on the Temp directory.</h6>

<center><img src ="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/NSIS/Exec.png"></img></center>

<h6></h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Timestamp.png"></img></center>

<h6>By classifying the samples by their creation dates, we can note the following remarks:
<ul>
<li>Four groups have a common date each, that is why they share the same code between them, attacking it by just editing the URL to connect or the objects to drop on the template.</li>
<li>Three groups can be noticed for DLLs, the samples from January 2020 with have different TTPs, the first variant in May 2020, which have an unused offset for the options and new TTPs and the second have just remove this offset.</li>
<li>Different elements are used for the parser (","; "__"; "/9S" ...) for splits the ref operation, URL of the C2 and the token for authentification.</li>
<li>All the samples use the "WinHttpGetIEProxyConfigForCurrentUser" method for getting the Internet Explorer proxy configuration for the current user for exploiting it on the malware.</li>
</ul></h6>

<h6>The first samples found in January 2020, this creates an old file extension for the mutex, once this allocates, this performs the reconnaissance actions (Disks, OS architecture, OS version...).</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJan2020/DllRegisterServer.png"></img></center>

<h6></h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJan2020/GetDiskSInfos.png"></img></center>

<h6>Once this done, this request the URL of the C2 to contact for getting the instructions to execute on the computer.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJan2020/SendDataToC2.png"></img></center>

<h6>This variant (May 2020) use another way for getting the URL to contact the C2. Instead of using an algorithm to decrypt the URL, this parse from a string, the token, URL of the C2 and the reference for the operations. Unlike the previous version, the implant checks the response of the C2 getting the code to execute.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJune2020/ExecuteActions.png"></img></center>

<h6>Like noted by <a href="https://twitter.com/iamwinstonm">d2hvYW1p</a>, this loads a dll by reflective method. The dll is PowershellRunner and allows to execute Powershell script without need to call Powershell. In the past have been used by Turla group (2019) and pushed on Empire project.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJune2020/PowerRef.png"></img></center>

<h6></h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJune2020/PowershellRunner.png"></img></center>

<h6>As an argument, this pushes a Powershell script for performing the authentication and get the code. The script has the same reference with Powerstats used by Muddywater (here with the POST request in 2018 but match with GET request used for getting the content with the Dropbox API in 2019).</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Muddy.png"></img></center>

<h6></h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Comp.png"></img></center>

<h6>This redirects and executes in memory the content of the code show on the console. Unfortunately, none of the C2 has given the content of the code to be executed. The implant doesn't check the content and the return of the C2, if the code isn't available the application will crash.</h6>

<h6>The list of the tokens and URL used can found <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/Muddywater/2020-07-02/CSV/Tokens.csv">here</a></h6>

<h6>Some agents have useless strings for generating high entropy and make harder the analysis. On the both case, this opens the dropped pdf file.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/AgentJune2020/Obfus.png"></img></center>

<h3>Victimology ?</h3>
<h4>Republic of Turkey</h4>
<h6>The Republic of Turkey has been targeted by several lures in connection with COVID-19 news on people tracing via mobile applications with an article and a fake report from the Ministry of Foreign Affairs. Turkey and Iran have long been regional rivals, but relations between two countries have deteriorated in recent years. Iran, Turkey and Russia began the Astana process in 2017 to support efforts to resolve the conflict in Syria, despite the fact that Iran and Russia support the government of Bashar Assad while Turkey supports the Syrian rebels. The current situation with the Turkish offensive and the events with Russia have considerably worsened the situation with the both countries.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/CyberDefense.png"></img></center>

<h6></h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/IPReport.png"></img></center>

<h6>Link to the original article : <a href="https://www.cybermagonline.com/korona-virusu-ve-siber-savunma">here</a></h6>
<h4>Kingdom of Saudi Arabia</h4>
<h6>This document focus on Second conference of Institutes of Public Administration and administrative development in the states members of the Gulf Cooperation Council was held in Riyadh (2012). The Qatari Ministry of Administrative Development conveyed invitations to the Public Administration and administrative development Institutes in the GCC member states to take part in the said conference and submit their working papers. Other invitations were also addressed to the governmental organs to attend. This possible, that the document used that it and is reused for this campaign.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/conf_golf1.png"></img></center>

<h6></h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/conf_golf2.png"></img></center>

<h4>UNRWA</h4>
<h6>Several reasons can be attributed to the fact that the organization is targeted, the first is the state of the finances of the organization which has been in deficits since 2018, the American aid towards the UNRWA was cut by Trump recently despite the fact that the united states had however given a help to COVID to this same organization. The administration of the United States having decided to punish the Palestinians following the declaration by Palestinian President Mahmoud Abbas that the US will no longer be a mediator in the peace process due to its in 2017 that Jerusalem as been recognition the capital of Israel.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/ArticleUNRWA2.png"></img></center>
<h6>The other reason would also be the recent officialization of a donation made by the Qatar to the organization and that knowing the current tensions between the two countries, the choice to target this organization would impose itself and more of the problems between the religious currents of Islam in these countries.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/ArticleUNRWA.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/unrwa.png"></img></center>
<h4>USA</h4>
<h6>The Trump Administration has imposed sanctions against Iran that target the Middle East’s maritime network on allegations of support for Tehran’s proliferation of weapons of mass destruction. It's the response to the various events between the USA, Saudi Arabia and Iran on the skirmishes with the US maritime units, the detention of the cargo ships and the attack on the attack on the refineries of Saudi Arabia.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/US1.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/Maldocs/US.png"></img></center>
<h6>Link to the original article : <a href="https://www.upi.com/Top_News/US/2020/06/08/US-sanctions-imposed-against-Iranian-shipping-go-into-effect/3231591668097/">here</a></h6>

<center>
<table>
<tr>
<th>Name of lure</th>
<th>Topic</th>
<th>Victim ?</th>
</tr>
<tr>
<td>Jawaejifahi.pdf</td>
<td>United Nations Relief and Works Agency for Palestine Refugees in the Near East</td>
<td>UNRWA Palestine</td>
</tr>
<tr>
<td>Jejytylavi.pdf</td>
<td>Second conference of Institutes of Public Administration and administrative development in the states members of the Gulf Cooperation Council (reuse an 2012 pdf ?)</td>
<td>Kingdom of Saudi Arabia</td>
</tr>
<tr>
<td>Jyhynyjegu.pdf</td>
<td>MINISTRY OF FOREIGN INFORMATION PROCESSING GENERAL MANAGER ASSISTANT 07.04.2020</td>
<td>Republic of Turkey - Ministry of Foreign Affairs</td>
</tr>
<tr>
<td>Kopexaekaeru.pdf</td>
<td>Unknown</td>
<td>Unknown</td>
<tr>
<td>Kytuqasylu.pdf</td>
<td>Corona Virus and Cyber Defense</td>
<td>Republic of Turkey</td>
</tr>
<tr>
<td>Lodolutaelae.pdf</td>
<td>U.S. sanctions imposed against Iranian shipping go into effect</td>
<td>USA</td>
</tr>
</table>
</center>

<h6>Looking at the metadata, we can notice the use of several different operating systems, which could presage that the group would have a dedicated cell for finding events and opportunities for their operations. Another example may be noticed is the fact that the decoy documents are dispersed in time and not grouped for a specific date.</h6>
<h6>A list of metadata can be available <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/Muddywater/2020-07-02/CSV/Metadata.csv">here</a>.</h6>


<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/Muddywater/2020-07-02/Pictures/CyberKill.png"></img></center>

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/Muddywater/2020-07-02/JSON/IOC-Muddywater-2020-07-02.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/Muddywater/2020-07-02/CSV/IOC-Muddywater-2020-07-02.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

<center>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Scheduled Task<br>Execution through API|https://attack.mitre.org/techniques/T1053<br>https://attack.mitre.org/techniques/T1106|
|Persistence|Scheduled Task<br>Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1053<br>https://attack.mitre.org/techniques/T1060|
|Privilege Escalation|Scheduled Task|https://attack.mitre.org/techniques/T1053|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012|

</center>

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/Muddywater/2020-07-02/JSON/MITRE-Muddywater-2020-07-02.json">Export in JSON</a></h6>
<h2>Yara rules <a name="Yara"></a></h2>
<h6>The Yara rules are available <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/Muddywater/2020-07-02/Yara/Yara_Rule_APT_Muddywater_June_2020_1.yar">here</a>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>
<ul>
<li><a href="https://twitter.com/RedDrip7/status/1272739150165245952">https://twitter.com/RedDrip7/status/1272739150165245952</a></li>
<li><a href="https://twitter.com/Timele9527/status/1272776776335233024">https://twitter.com/Timele9527/status/1272776776335233024</a></li>
<li><a href="https://twitter.com/ShadowChasing1/status/1276708757943144448">https://twitter.com/ShadowChasing1/status/1276708757943144448</a></li>
<li><a href="https://twitter.com/iamwinstonm/status/1273195438619967489">https://twitter.com/iamwinstonm/status/1273195438619967489</a></li>
</ul>

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>
<ul>
<li><a href="https://app.any.run/tasks/bb956e3a-36a5-4106-a50e-567776faf034">New Health Protocols.v13.exe</a></li>
<li><a href="https://app.any.run/tasks/08f3247b-1550-4b06-9eeb-7da500e4d74a">Corona Virüsü ve Siber Savunma8.exe</a></li>
<li><a href="https://app.any.run/tasks/e71572a8-2ac9-4002-9401-284fe39d318c">Invite3.exe</a></li>
<li><a href="https://app.any.run/tasks/a3015868-f51c-4dc5-908a-0c47f6c54cf1">announcement.exe</a></li>
<li><a href="https://app.any.run/tasks/cba85da2-64ef-4186-a32e-0c06599b6898">bd43f26aedba541c3ed23cc0ffe572c5.virus</a></li>
<li><a href="https://app.any.run/tasks/1fb528c2-d88c-430b-86c8-c6ff656da3c5">UNRWA-ServerRequest1145.exe</a></li>
</ul>

<h6> References: <a name="References"></a></h6>
<ul>
<li><a href="https://github.com/EmpireProject/PSInject/">PS Inject (Empire)</a></li>
<li><a href="https://www.iiss.org/blogs/analysis/2018/09/trump-unrwa-aid-cut/">What does Trump’s UNRWA aid cut mean for Palestinians and the Middle East ?</a></li>
<li><a href="https://www.hybrid-analysis.com/sample/ecc711fecb38c3557a5c2b1e9a46e9cf59b63a0c0203a7f4953af05d11582c02/5c19d7907ca3e126264d7cc8"> Powerstats ref (2018)</a></li>
</ul>

