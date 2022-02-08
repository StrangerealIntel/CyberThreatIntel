# Note about Antlion group
#### Antlion is a recently declared APT group which is a group based in China. The victomology is princpaly axed to Tawain on focused financial institutions and a manufacture.The different reason according to the economic dependence of Taiwan regarding to China and rest on the world leaders in advanced semiconductor technology.
#### Some Chinese groups like ```Chimera``` on the ```Operation Skeleton Key``` have targeted Taiwanese chip and airline companies in the last years for the ```MSS``` as a view to providing technologies and economic intelligence.

#### On the few samples that available, we have noted some matches with the structure of other tools of another Chinese APT23 (FireEye) / Earth Centaur / Tropic Trooper (Trend Micro) / Pirate Panda (CrowdStrike) :

#### The loader called ```NeraPack``` from ```APT23``` perform the decryption of the encrypted payload pushed by the webshells and launch it in the memory. The loader has one function that decrypt the encrypted data from DES algorithm with a key that hardcoded inside the C# program.

#### At the beginning, the key was clearly in the loader, then migrate to a base64 string in the argument of the execution of the program which is initially decoded by native function (Convert.FromBase64String) to a custom function for the same purpose. This custom function have the same name and code on the latest sample of ```NeraPack``` and ```XPack```.

<p style="center"><img src="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/China/APT/Antlion/pic/Match1.png"></img></p>

#### The decryption process has a similar code except that the names of some variables change.

<p style="center"><img src="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/China/APT/Antlion/pic/Match2.png"></img></p>

#### By this way, the yara rule that I have made for ```NeraPack``` triggers easily both groups of samples.

```
> .\yara64.exe .\Orion\APT\APT_APT23_NeraPack_Dec_2021_1.yara -r "C:\Users\MIRA\Downloads\Pirate Panda"
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\3ad24a438b9a67e4eff7ca7d34b06d5efc24b824e3e346488d534532faa619da
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\6b1b231a7d190651f8c89072e2514aade288dfe6bd87ea62171b6ecffe13d63e
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\12425edb2c50eac79f06bf228cb2dd77bb1e847c4c4a2049c91e0c5b345df5f2
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\e488f0015f14a0eff4b756d10f252aa419bc960050a53cc04699d5cc8df86c8a
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\e4a15537f767332a7ed08009f4e0c5a7b65e8cbd468eb81e3e20dc8dfc36aeed
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\321febf2bc5603b58628e3a82fb063027bf175252a3b30869eccb90a78e59582
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\dd1afc083b7d82444fcec99e01e8293d51f744201cb968346ec334fb5dd32495
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Pirate Panda\NeraPack\a64e0c21494811ededf5d8af41b00937c1d5787d63dfcc399a7f32c19a553c99
> .\yara64.exe .\Orion\APT\APT_APT23_NeraPack_Dec_2021_1.yara -r "C:\Users\MIRA\Downloads\Antlion\"
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Antlion\\xpack\390460900c318a9a5c9026208f9486af58b149d2ba98069007218973a6b0df66
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Antlion\\xpack\12425edb2c50eac79f06bf228cb2dd77bb1e847c4c4a2049c91e0c5b345df5f2
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Antlion\\xpack\e4a15537f767332a7ed08009f4e0c5a7b65e8cbd468eb81e3e20dc8dfc36aeed
APT_APT23_NeraPack_Dec_2021_1 C:\Users\MIRA\Downloads\Antlion\\xpack\e488f0015f14a0eff4b756d10f252aa419bc960050a53cc04699d5cc8df86c8a
```

#### We can also note that the XPack reference was present in ```Nerapack``` samples with xPack (321febf2bc5603b58628e3a82fb063027bf175252a3b30869eccb90a78e59582).

#### The initial vector wasn't clearly specified but announced by Symantec that "one instance they were seen utilizing the MSSQL service to execute system commands" and "used malicious emails to gain initial access to victim networks", that's to note that APT23 used ```ProxyLogon``` exploits and webshells for interact and discover the victim infrastructure.

#### Both groups try to exploit SMB shares as one method of lateral movement. Antlion use a small tool that check the active sessions by ```NetSessionEnum``` for spread on others targets of interest.

<p style="center"><img src="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/China/APT/Antlion/pic/Match3.png"></img></p>

#### As last point of similarity, remains the methods used for data extraction via legitimate applications (winrar, rclone...) or native to the system (BITS), the creation of backdoor or RAT and the use of red team tools (Mimikatz, procdump, SharpHound...).

#### If we add that Antlion is announced as believed to have been involved in espionage activities since at least 2011 by Symantec make sense to that Trend Micro have wrote on their article on ```USBFerry``` tool of ```APT23```.

<p style="center"><img src="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/China/APT/Antlion/pic/Match4.png"></img></p>

#### With all the elements, we can show to demonstrate links of assignment and sharing of tools between these two groups at least as a sub-group formed temporarily for the needs of particular objectives given by the MSS or the same group. Unfortunately, the lack of samples and information on the TTPs doesn't allow attribution at 100%.

### Links :

<ul>
<li><a href="https://www.semiconductors.org/chinas-share-of-global-chip-sales-now-surpasses-taiwan-closing-in-on-europe-and-japan/">China’s Share of Global Chip Sales Now Surpasses Taiwan’s, Closing in on Europe’s and Japan’s</a>
<li><a href="https://medium.com/attivotechblogs/lateral-movement-using-smb-session-enumeration-f4b1b17b6ee8">Lateral Movement Using SMB Session Enumeration</a>
<li><a href="https://www.trendmicro.com/en_us/research/20/e/tropic-troopers-back-usbferry-attack-targets-air-gapped-environments.html">Tropic Trooper’s USBferry Targets Air-Gapped Networks</a>
<li><a href="https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/china-apt-antlion-taiwan-financial-attacks">Antlion: Chinese APT Uses Custom Backdoor to Target Financial Institutions in Taiwan</a>
</ul>

### Yara :

- Antlion
    -  [EHAGBPSL](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_Antlion_EHAGBPSL_Feb_2022_1.yara)
    -  [XPack](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_Antlion_xPack_Feb_2022_1.yara)
    -  [NetSessionEnum](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_Antlion_NetSessionEnum_Feb_2022_1.yara)
- APT23
    -  [ChiserClient](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_ChiserClient_Dec_2021_1.yara)
    -  [Gh0st RAT](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_Gh0stRAT_Dec_2021_1.yara)
    -  [NeraPack](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_NeraPack_Dec_2021_1.yara)
    -  [Smilesvr](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_Smilesvr_Dec_2021_1.yara)
    -  [Smilesvrdrp](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_Smilesvrdrp_Dec_2021_1.yara)
    -  [USBFerry Unpacked x64](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_USBFerry_May_2020_1.yara)
    -  [USBFerry Packed x64](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_USBFerry_May_2020_2.yara)
    -  [USBFerry Unpacked x86](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_USBFerry_May_2020_3.yara)
    -  [USBFerry Unpacked x86 (Variant)](https://github.com/StrangerealIntel/Orion/blob/main/APT/APT_APT23_USBFerry_May_2020_4.yara)
