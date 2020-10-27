<h4>September was a very busy month for news and vulnerability. With each new vulnerability allowing rights to be pivoted and raised quickly in an infrastructure, Ruyk quickly exploits it to the full to quickly make the event profitable.</h4>
<h4>By various response responses to incidents and articles dedicated to the news on TTPs used, several strains were found in the September month:</h4>
<h3>New builds in the old templates</h3>

<h4>This begins by load all the sensitive strings this can be used for the rest of the process.</h4>

```asm
0x3500557a  xor    eax, eax
0x3500557c  mov    dword [var_3ch], eax
0x3500557f  mov    dword [var_38h], eax
0x35005582  mov    word [var_34h], ax
0x35005586  push   0xa   ; 10
0x35005588  lea    ecx, [var_3ch]
0x3500558b  push   ecx
0x3500558c  mov    edx, dword [section..data] ; 0x3501c000
0x35005592  push   edx
0x35005593  call   init_process
0x35005598  add    esp, 0xc
0x3500559b  lea    eax, [var_3ch]
0x3500559e  mov    dword [var_ch], eax
0x350055a1  mov    ecx, dword [var_ch]
0x350055a4  add    ecx, 1
0x350055a7  mov    dword [var_40h], ecx
```

<h4>This use all the strings as reference for call the API functions and strings by calls.</h4>

<h4>Firstly, this enumerate processes by "CreateToolhelp32Snapshot" for parse the running process and try to open the following process with "OpenProcess". If works write the payload on process by "WriteProcessMemory" call and create another thread with "CreateRemoteThread" call.</h4>

```
// target only x86 process
explorer.exe
lsaas.exe
lan.exe
csrss.exe
// Fake typo
Ncsrss.exe
```

<h4>This enumerate processes a second time by "CreateToolhelp32Snapshot" for check the process and kill all the matchs. Also check the services running on the machine and stop them.</h4>

```
// list of process to kill
virtual
vmcomp
vmwp
veeam
backup
Backup
xchange
sql
dbeng
sofos
calc
ekrn
zoolz
encsvc
excel
firefoxconfig
infopath
msaccess
mspub
mydesktop
ocautoupds
ocomm
ocssd
onenote
oracle
outlook
powerpnt
sqbcoreservice
steam
synctime
tbirdconfig
thebat
thunderbird
visio
word
xfssvccon
tmlisten
pccntmon
cntaosmgr
ntrtscan
mbamtray
```

```
// list of services to kill
vmcomp
vmwp
veeam
Back
xchange
ackup
acronis
sql
Enterprise
Sophos
Veeam
AcrSch
Antivirus
Antivirus
bedbg
DCAgent
EPSecurity
EPUpdate
Eraser
EsgShKernel
FA_Scheduler
IISAdmin
IMAP4
MBAM
Endpoint
Afee
McShield
task
mfemms
mfevtp
mms
MsDts
Exchange
ntrt
PDVF
POP3
Report
RESvc
sacsvr
SAVAdmin
SamS
SDRSVC
SepMaster
Monitor
Smcinst
SmcService
SMTP
SNAC
swi_
CCSF
TrueKey
tmlisten
UI0Detect
W3S
WRSVC
NetMsmq
ekrn
EhttpSrv
ESHASRV
AVP
klnagent
wbengine
KAVF
mfefire
```

<h4>This execute a command for add an Run key for the persistence, if already exist, this delete it and rewrite it.</h4>

```do
cmd.exe /C REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" /v "EV" /t REG_SZ /d [$Path Exe]

cmd.exe /C REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" /v "EV" /f
```

<h4>Some samples have the capacity to use "Wake On Lan" for spreading on the network infrastructure. This write a copy of himself and execute it in creating a new thread in pushing “8 LAN” as argument. Each one have a sleep call for wait time before encryption.</h4>
<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RUYK/2020-10-27/Pictures/WOL.png"></img></p>

<h4>This parse the disks with "GetDriveTypeA" calls for get local and network drives. This check some strings for check if the disks are valid and ignore some extensions to encrypt.</h4>

```
// List of strings checked on the path to parsing process
Ahnlab
Chrome
Mozilla
Windows
$Recycle.bin
```

```
// List of file extensions to ignore on the encryption process
.dll
.hrmlog
.exe
.ini
.lnk
.bootmgr
.boot
```

<h4>This disable the windows automatic repair option on the boot and delete the VSS saves for avoid to recovery the data :</h4>

```
cmd.exe /c "bcdedit /set {default} recoveryenabled No & bcdedit /set {default}"
cmd.exe /c "bootstatuspolicy ignoreallfailures"
cmd.exe /c "vssadmin.exe Delete Shadows /all /quiet"
cmd.exe /c "WMIC.exe shadowcopy delete"
```

<h4>In searching on the archives, we can note that the same exact behavior that analysed on March 2020 by Fortinet. This allows to deduce that the group have build in emergency somes payloads for exploit quickly the vulnerability.</h4>

<table>
    <tr>
        <th>Hash</th>
        <th>Extension</th>
        <th>Sig</th>
    </tr>
    <tr>
        <td>bbbf38de4f40754f235441a8e6a4c8bdb9365dab7f5cfcdac77dbb4d6236360b</td>
        <td><center>.RYK</center></td>
        <td>RUYK_Sept_V1_WOL</td>
    </tr>
    <tr>
        <td>cfe1678a7f2b949966d9a020faafb46662584f8a6ac4b72583a21fa858f2a2e8</td>
        <td><center>.RYK</center></td>
        <td>RUYK_Sept_V1_WOL</td>
    </tr>
    <tr>
        <td>bbbf38de4f40754f235441a8e6a4c8bdb9365dab7f5cfcdac77dbb4d6236360b</td>
        <td><center>.RYK</center></td>
        <td>RUYK_Sept_V1_WOL</td>
    </tr>
</table>

<h4>Reference : </h4>
<a href="https://www.fortinet.com/blog/threat-research/ryuk-revisited-analysis-of-recent-ryuk-attack">Ryuk Revisited - Analysis of Recent Ryuk Attack</a>

<h4>Some samples on lastest pool of September are packed with another packer "Obsidium" which use lot Xor and permutation operations for load this own dll on a new thread in decoding finally the encrypted data with the code inside the obsidium dll.</h4>

```cpp
uint32_t uVar1;
uint32_t uVar2;
int32_t iVar3;
int32_t iVar4;
int32_t iVar5;
uint32_t uVar6;
uint8_t *puVar7;
uint32_t uVar8;
int32_t var_10h;
int32_t var_ch;
int32_t var_8h;
int32_t var_4h;

var_10h = param_1 ^ 0x117584c9;
var_ch = param_1 ^ 0xcc213749;
*(int32_t *)0xf04589ba = *(int32_t *)0xf04589ba - (int32_t)&stack0xfffffffc;
var_8h = param_1 ^ 0x85a228df;
var_4h = param_1 ^ 0x257bd6b0;
// PushCode
func_0x3502c145(0x3502c5f3, 0x5f81, &var_10h);
puVar7 = (uint8_t *)0x3502c5f3;
uVar1 = 0xe3e;
uVar6 = 1;
uVar8 = 0;
do {
    while ((4 < uVar1 && (uVar8 < 0x80000000))) 
    {
        iVar3 = uVar6 + *puVar7;
        iVar4 = iVar3 + (uint32_t)puVar7[1];
        iVar5 = iVar4 + (uint32_t)puVar7[2];
        uVar6 = iVar5 + (uint32_t)puVar7[3];
        uVar1 = uVar1 - 4;
        puVar7 = puVar7 + 4;
        uVar8 = uVar8 + iVar3 + iVar4 + iVar5 + uVar6;
    }
    uVar2 = uVar6 + *puVar7;
    uVar6 = uVar2 % 0xfff1;
    uVar1 = uVar1 - 1;
    puVar7 = puVar7 + 1;
    uVar8 = (uVar8 + uVar2) % 0xfff1;
    } while (uVar1 != 0);
return;
```

<h4>On the memory trace, we can note the strings in memory show the reference to the packer used for hide the RYUK ransomware.</h4>
<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RUYK/2020-10-27/Pictures/Str.png"></img></p>

<h4>As said before, the payload write a copy of himself and execute by a new thread with "8 LAN" argument, the last samples have a common pattern :</h4>

```
// Example of dropped files on the disk
%temp%\PaRyHBUIXlan.exe
%temp%\pBbowloYglan.exe
%temp%\nXsTetgJilan.exe
// Pattern 
-> %temp%\\[a-zA-Z]{9}lan.exe
```

<h4>This use as used icacls for change the rights attribution and parse the disks, this give the current process graph (Single + WOL).</h4>
<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RUYK/2020-10-27/Pictures/Process.png"></img></p>

<h4>The last samples have the same algorithms for decrypt the code to execute but have some deleted parts that the code for the "LAN spreading" functionality (give an offset on comparative analysis).</h4>
<p align="center"><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RUYK/2020-10-27/Pictures/Files.png"></img></p>

<table>
    <tr>
        <th>Hash</th>
        <th>Extension</th>
        <th>Sig</th>
    </tr>
    <tr>
        <td>92f124ea5217f3fe5cbab1c37a961df0437d5a9cbde1af268c60c4b3194b80ed</td>
        <td><center>.aapp</center></td>
        <td>RUYK_Sept_V2_S</td>
    </tr>
    <tr>
        <td>d0d7a8f588693b7cc967fb4069419125625eb7454ba553c0416f35fc95307cbe</td>
        <td><center>.aapp</center></td>
        <td>RUYK_Sept_V2_WOL</td>
    </tr>
    <tr>
        <td>d7333223dcc1002aae04e25e31d8c297efa791a2c1e609d67ac6d9af338efbe8</td>
        <td><center>.aapp</center></td>
        <td>RUYK_Sept_V2_S</td>
    </tr>
</table>

<h4>For resume, RYUK group haven't really change the ransomware implant but have just take the opportunity to edit a few payloads to make the most of the infection returns before the majority of security managers fix the Zerologon vulnerability of theirs informations systems.</h4>

<h4>Additionnal ressources :</h4>
<ul>
<li><a href="https://bazaar.abuse.ch/browse/tag/Ryuk/">All the samples RYUK (Sept 2020)</a></li>
<li><a href="https://github.com/StrangerealIntel/DailyIOC/tree/master/2020-10-27/RYUK">Yara Rules for RYUK ramsomware (Sept 2020)</a></li>
<li><a href="https://redcanary.com/blog/ryuk-ransomware-attack/">The Third Amigo: detecting Ryuk ransomware (Feb 2020)</a></li>
<li><a href="https://www.financialcert.tn/2020/10/14/ryuks-return/">Ryuk’s Return (Sept 2020 -> TTPs, knownedge on Incident Response)</a></li>
<li><a href="https://www.kroll.com/en/insights/publications/cyber/cve-2020-1472-zerologon-exploit-detection-cheat-sheet">CVE-2020-1472 (Zerologon) Exploit Detection Cheat Sheet (Oct 2020 -> Explaination + Yara rules</a></li>
</ul>
