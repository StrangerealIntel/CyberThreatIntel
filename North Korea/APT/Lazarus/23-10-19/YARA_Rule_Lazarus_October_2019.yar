*
   YARA Rule Set
   Author: Arkbird_SOLG
   Date: 2019-10-26
   Reference: https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_Lazarus_VBA_Malware_Oct19_1 {
   meta:
      description = "연인심리테스트.xls"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-26"
      hash1 = "a7ff0dfc2456baa80e6291619e0ca480cc8f071f42845eb8316483e077947339"
   strings:
      $x1 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x2 = "C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $s3 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Micr" wide
      $s4 = "$pif.FileName=\"cmd.exe\"" fullword ascii
      $s5 = "C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE" fullword ascii
      $s6 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#" wide
      $s7 = "if([System.IO.File]::Exists($spth)){try{$srsl=Get-Content -Path $spth; Remove-Item -Path $spth; if($srsl.GetType().FullName -eq " ascii
      $s8 = "$bdy=\"--\" + (Get-Date -Format yyyy-MM-dd-hh-mm-ss-fffffff) + \"--\"" fullword ascii
      $s9 = "*\\G{00020813-0000-0000-C000-000000000046}#1.9#0#C:\\Program Files (x86)\\Microsoft Office\\Root\\Office16\\EXCEL.EXE#Microsoft " wide
      $s10 = "$spth=[System.IO.Path]::GetTempFileName()" fullword ascii
      $s11 = "Start-Process $scmd" fullword ascii
      $s12 = "$rq.UserAgent = \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/5" ascii
      $s13 = "if($nmx -gt $rsp.ContentLength){$nmx=$rsp.ContentLength}" fullword ascii
      $s14 = "if([System.IO.File]::Exists($spth)){try{$srsl=Get-Content -Path $spth; Remove-Item -Path $spth; if($srsl.GetType().FullName -eq " ascii
      $s15 = "$pif = New-Object System.Diagnostics.ProcessStartInfo" fullword ascii
      $s16 = "$p = New-Object System.Diagnostics.Process" fullword ascii
      $s17 = "$scmd=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)" fullword ascii
      $s18 = "$rq=[System.Net.WebRequest]::create($pxy + \"?v=\" + $unm)" fullword ascii
      $s19 = "$ip=(Test-Connection -ComputerName $hs -Count 1  | Select -ExpandProperty IPV4Address).Address" fullword ascii  
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule APT_Lazarus_PS1_Malware_Oct19_1 {
   meta:
      description = "sopiiubuvsclwukz.ps1"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-26"
      hash1 = "360431100aa6da78b577cc8b4606fa66e6191056fac7c42929abec5a4402da7a"
   strings:
      $s1 = "$pif.FileName=\"cmd.exe\"" fullword ascii
      $s2 = "if([System.IO.File]::Exists($spth)){try{$srsl=Get-Content -Path $spth; Remove-Item -Path $spth; if($srsl.GetType().FullName -eq " ascii
      $s3 = "$bdy=\"--\" + (Get-Date -Format yyyy-MM-dd-hh-mm-ss-fffffff) + \"--\"" fullword ascii
      $s4 = "$spth=[System.IO.Path]::GetTempFileName()" fullword ascii
      $s5 = "Start-Process $scmd" fullword ascii
      $s6 = "$rq.UserAgent = \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/5" ascii
      $s7 = "$pbdy=stoub(\"`r`n`r`n--\" + $bdy + \"`r`nContent-Disposition: form-data; name=`\"_webident_f`\"`r`n`r`n\" + $tid + \"`r`n--\" +" ascii
      $s8 = "if([System.IO.File]::Exists($spth)){try{$srsl=Get-Content -Path $spth; Remove-Item -Path $spth; if($srsl.GetType().FullName -eq " ascii
      $s9 = "$fnm=-join((48..57)|Get-Random -Count 12|%{[char]$_})+\".dat\"" fullword ascii
      $s10 = "$pif = New-Object System.Diagnostics.ProcessStartInfo" fullword ascii
      $s11 = "$p = New-Object System.Diagnostics.Process" fullword ascii
      $s12 = "$scmd=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)" fullword ascii
      $s13 = "$rq=[System.Net.WebRequest]::create($pxy + \"?v=\" + $unm)" fullword ascii
      $s14 = "$ip=(Test-Connection -ComputerName $hs -Count 1  | Select -ExpandProperty IPV4Address).Address" fullword ascii
      $s15 = "if($nmx -gt $rsp.ContentLength){$nmx=$rsp.ContentLength}" fullword ascii
      $s16 = "$global:tid=Get-Random -Minimum 128 -Maximum 16383" fullword ascii
      $s17 = "a; name=`\"file`\"; filename=`\"\" + $fnm + \"`\"`r`nContent-Type: octet-stream`r`n`r`n\")" fullword ascii
      $s18 = "$rq.ContentLength=$pbdy.Length + $bds + $ebdy.Length;" fullword ascii
      $s19 = "\"`r`nContent-Disposition: form-data; name=`\"_webident_s`\"`r`n`r`n\" + $rid + \"`r`n--\" + $bdy + \"`r`nContent-Disposition: f" ascii 
    condition:
      uint16(0) == 0xbbef and filesize < 30KB and
      8 of them
}

rule APT_Lazarus_VBA_Malware_Oct19_2 {
   meta:
      description = "샘플_기술사업계획서(벤처기업평가용).doc"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-26"
      hash1 = "761bcff9401bed2ace80b85c43b230294f41fc4d1c0dd1ff454650b624cf239d"
   strings:
      $s1 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s2 = "000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual Basic For Appl" wide
      $s3 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\system32\\stdole2.tlb#OLE Automation" fullword wide
      $s4 = "https://nzssdm.com/assets/mt.dat'" fullword ascii
      $s5 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files\\Microsoft Office\\Root\\Office16\\MSWORD.OLB#Microsoft Word " wide
      $s6 = "SO.DLL#" fullword ascii
      $s7 = "data) - " fullword ascii
      $s8 = "command  As S" fullword ascii
      $s9 = "curl -o  " fullword ascii
      $s10 = "nd(cdata ) - L" fullword ascii
      $s11 = "und(cdat@a) - L" fullword ascii
      $s12 = "ypass -f" fullword ascii
      $s13 = "systema" fullword ascii
      $s14 = "<a:clrMap xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" acce" ascii
      $s15 = "len - 1" fullword ascii
      $s16 = "ta) - L" fullword ascii
      $s17 = "ata) - L" fullword ascii
      $s18 = "Header Char" fullword wide
      $s19 = "4000*4000" fullword wide /* hex encoded string '@@' */
   condition:
      uint16(0) == 0xcfd0 and filesize < 900KB and
      8 of them
}

rule APT_Lazarus_Malware_Oct19_1 {
   meta:
      description = "public.dll"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-26"
      hash1 = "ccafbcff1596e3dfd28dcb97a5ba85e6845e69464742edfe136fe09bbec86ba1"
   strings:
      $s1 = "Winhttp.dll" fullword ascii
      $s2 = "fona64.dll" fullword ascii
      $s3 = "Wsock32.dll" fullword ascii
      $s4 = "https://www.juliesoskin.com/includes/common/list.php" fullword ascii
      $s5 = "Cookie: _ga=%s%02d%d%d%02d%s; gid=%s%02d%d%03d%s" fullword ascii
      $s6 = "https://www.valentinsblog.de/wp-admin/includes/list.php" fullword ascii
      $s7 = "https://www.necaled.com/modules/applet/list.php" fullword ascii
      $s8 = "operator co_await" fullword ascii
      $s9 = "cmnashwkweu" fullword ascii
      $s10 = ".%d%05d%04d" fullword ascii
      $s11 = "Accept-Language: az-Arab" fullword ascii
      $s12 = "Accept-Language: de-CH" fullword ascii
      $s13 = "Accept-Language: en-US,en;q=0.5" fullword ascii
      $s14 = "__swift_2" fullword ascii
      $s15 = "__swift_1" fullword ascii
      $s16 = "GA1.%d." fullword ascii
      $s17 = ".?AVCWebPacket@@" fullword ascii
      $s18 = "TODO: layout property page" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      ( pe.imphash() == "912d2b0681d67169c9ee0b4cead2c366" and pe.exports("cmnashwkweu") or 8 of them )
}

rule APT_Lazarus_HWP_Malware_Oct19_1 {
   meta:
      description = "lazarus.hwp"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-26"
      hash1 = "d4f055d170fd783ae4f010df64cfd18d8fa9a971378298eb6e863c60f57b93e3"
   strings:
      $s1 = ":\\Users\\USER\\AppData\\Local\\Temp" fullword wide
      $s2 = "JScriptVersion" fullword wide
      $s3 = "DefaultJScript" fullword wide
      $s4 = "FileHeader" fullword wide
      $s5 = "BinData" fullword wide
      $s6 = "\\prv0000024c3bc4.gif" fullword wide
      $s7 = "Section1" fullword wide
      $s8 = "Section0" fullword wide
      $s09 = "_LinkDoc" fullword wide
      $s10 = "(bE1.Ucv" fullword ascii
      $s11 = "xxxkkk]]]PPPCCC555(((" fullword ascii
      $s12 = "DocOptions" fullword wide
      $s13 = "BIN0001.PS" fullword wide
      $s14 = "PrvText" fullword wide
      $s15 = "PrvImage" fullword wide
      $s16 = "8, 0, 0, 466 WIN32LEWindows_7" fullword wide
      $s17 = "X0xT0pH " fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and
      8 of them
}

rule APT_Lazarus_PS1_Malware_Oct19_2 {
   meta:
      description = "snphhuatvsbkw.ps1"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-26"
      hash1 = "4503a194e5064595e36ef01ed87c24203acce56f308af23e2563e71f890b0188"
   strings:
      $s1 = "$global:auri=\"https://towingoperations.com/chat/chat.php\",\"https://baseballcharlemagnelegardeur.com/wp-content/languages/comm" ascii
      $s2 = "e=`\"file`\"; filename=`\"\" + $fnm + \"`\"`r`nContent-Type: octet-stream`r`n`r`n\")" fullword ascii
      $s3 = "$pif.FileName=\"cmd.exe\"" fullword ascii
      $s4 = "if([System.IO.File]::Exists($spth)){try{$srsl=Get-Content -Path $spth; Remove-Item -Path $spth; if($srsl.GetType().FullName -eq " ascii
      $s5 = "$bdy=\"--\" + (Get-Date -Format yyyy-MM-dd-hh-mm-ss-fffffff) + \"--\"" fullword ascii
      $s6 = "$spth=[System.IO.Path]::GetTempFileName()" fullword ascii
      $s7 = "Start-Process $scmd" fullword ascii
      $s8 = "$rq.UserAgent = \"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" ascii
      $s9 = "php\",\"https://www.tangowithcolette.com/pages/common.php\"" fullword ascii
      $s10 = "if([System.IO.File]::Exists($spth)){try{$srsl=Get-Content -Path $spth; Remove-Item -Path $spth; if($srsl.GetType().FullName -eq " ascii
      $s11 = "$fnm=-join((48..57)|Get-Random -Count 12|%{[char]$_})+\".dat\"" fullword ascii
      $s12 = "$pif = New-Object System.Diagnostics.ProcessStartInfo" fullword ascii
      $s13 = "$p = New-Object System.Diagnostics.Process" fullword ascii
      $s14 = "$scmd=[System.Text.ASCIIEncoding]::UTF8.GetString($buf,12,$nmlen)" fullword ascii
      $s15 = "$rq=[System.Net.WebRequest]::create($pxy + \"?v=\" + $unm)" fullword ascii
      $s16 = "$ip=(Test-Connection -ComputerName $hs -Count 1  | Select -ExpandProperty IPV4Address).Address" fullword ascii
      $s17 = "if($nmx -gt $rsp.ContentLength){$nmx=$rsp.ContentLength}" fullword ascii
      $s18 = "$global:tid=Get-Random -Minimum 128 -Maximum 16383" fullword ascii
      $s19 = "$rq.ContentLength=$pbdy.Length + $bds + $ebdy.Length;" fullword ascii
   condition:
      uint16(0) == 0x6724 and filesize < 40KB and
      8 of them
}

rule APT_Lazarus_macOS_Malware_Oct19_1 {
   meta:
      description = "mt.dat"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-27"
      hash1 = "f9ffb15a6bf559773b0df7d8a89d9440819ab285f17a7b0a98626c14164d170f"
   strings:
      $s1 = "https://towingoperations.com/chat/chat.php" fullword ascii
      $s2 = "https://baseballcharlemagnelegardeur.com/wp-content/languages/common.php" fullword ascii
      $s3 = "_ReplySessionExec" fullword ascii
      $s4 = "mh_execute_header" fullword ascii
      $s5 = "@___stack_chk_fail" fullword ascii
      $s6 = "/bin/bash -c \"" fullword ascii
      $s7 = "https://www.tangowithcolette.com/pages/common.php" fullword ascii
      $s8 = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" fullword ascii
      $s9 = "_ReplyExec" fullword ascii
      $s10 = "ssionExec" fullword ascii
      $s11 = "@_gethostbyname" fullword ascii
      $s12 = "@_gethostname" fullword ascii
      $s13 = "sh -c \"" fullword ascii
      $s14 = "OtherShellCmd" fullword ascii
      $s15 = "_ReplyGetConfig" fullword ascii
      $s16 = "_ReplyOtherShellCmd" fullword ascii
      $s17 = "content-type: multipart/form-data" fullword ascii
      $s18 = "GetMsgHeaderSize" fullword ascii  
   condition:
      uint16(0) == 0xfacf and filesize < 80KB and
      8 of them
}

rule APT_Lazarus_macOS_Malware_Oct19_2 {
   meta:
      description = "Flash Player"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Lazarus/23-10-19/analysis.md"
      date = "2019-10-27"
      hash1 = "735365ef9aa6cca946cfef9a4b85f68e7f9f03011da0cf5f5ab517a381e40d02"
   strings:
      $s1 = "launchctl load -w \"%s/Library/LaunchAgents/%s\"" fullword ascii
      $s2 = "_mh_execute_header" fullword ascii
      $s3 = "<key>Program</key>" fullword ascii
      $s4 = "/bin/bash -c \"" fullword ascii
      $s5 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Safari/537.36" fullword ascii
      $s6 = "@_gethostbyname" fullword ascii
      $s7 = "@_gethostname" fullword ascii
      $s8 = "sh -c \"" fullword ascii
      $s9 = "https://crabbedly.club/board.php" fullword ascii
      $s10 = "https://indagator.club/board.php" fullword ascii
      $s11 = "https://craypot.live/board.php" fullword ascii
      $s12 = "com.adobe.macromedia.flash.plist" fullword ascii
      $s13 = "<key>RunAtLoad</key>" fullword ascii
      $s14 = "%s/Library/LaunchAgents/%s" fullword ascii
      $s15 = "content-type: multipart/form-data" fullword ascii
      $s16 = "@_getpwuid" fullword ascii
      $s17 = "chmod +x \"%s/%s\"" fullword ascii
      $s18 = "@___stack_chk_fail" fullword ascii
      $s19 = "/usr/lib/libSystem.B.dylib" fullword ascii
   condition:
      uint16(0) == 0xfacf and filesize < 100KB and
      8 of them
}
