import "pe"

rule Mal_BozokRAT_July_2020_1 {
   meta:
      description = "Detect BozokRAT used by APT Patchwork in July 2020"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/tree/master/Indian/APT/Patchwork/2020-07-23/Analysis.md"
      date = "2020-07-13"
      hash1 = "dfe18346db405af2484064e80b5c0124bc80ca84d39b90e1aa5d5592c479a904"
   strings:
      $s1 = "ouemm/emm" fullword ascii
      $s2 = "Vtfs43/emm" fullword ascii 
      $s3 = "bewbqj43/emm" fullword ascii
      $s4 = "lfsofm43/emm" fullword ascii
      $s5 = "Tifmm43/emm" fullword ascii
      $s6 = "apvui.exe" fullword ascii
      $s7 = "NisSrv.exe" fullword ascii
      $s8 = "k7tsecurity.exe" fullword ascii
      $s9 = "AkSA.exe" fullword ascii
      $s10 = "uiSeAgnt.exe" fullword ascii
      $s11 = "Tray.exe" fullword ascii
      $s12 = "Prd.EventViewer.exe" fullword ascii
      $s13 = "PSUAMain.exe" fullword ascii
      $s14 = "zatray.exe" fullword ascii
      $s15 = "egui.exe" fullword ascii
      $s16 = "onlinent.exe" fullword wide
      $s17 = "gy|ix;;:$nff" fullword ascii
      $s18 = "https://en.wikipedia.org/wiki/Main_Page" fullword ascii /* legit site used as test for connectivity*/
      $s19 = "https://facebook.com" fullword ascii /* legit site used as test for connectivity*/
      $s20 = "https://google.com-" fullword ascii /* legit site used as test for connectivity*/
      $s21 = "--*****-------" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and ( pe.imphash() == "75b883fc692473a6eb7f309e3f1a432d" or 15 of them )
}

rule Mal_BadNews_2016_OPChina_1 {
   meta:
      description = "Detect BadNews used by APT Patchwork in 2016 against China"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/tree/master/Indian/APT/Patchwork/2020-07-23/Analysis.md"
      date = "2020-07-13"
      hash1 = "35b4b9e6ce105affb3d9516f0101b771f78ee61540329f8fd7de5868ca3291ef"
   strings:
      $s1 = ":\\System Volume Information\\config" fullword ascii
      $s2 = "Content-LengtGetKeyboardLayouGetConsoleWindowapplication/x-ww" fullword ascii 
      $s3 = "\\Microsoft\\Templates\\msvcrt.dll" fullword ascii
      $s4 = "Host:DispatchMessageAGetModuleHandleAInternetConnectAHttpSendRequestAHttpOpenRequestARegQueryValueExA" fullword ascii
      $s5 = "??.dat" fullword ascii
      $s6 = "%04d/%02d/%02d %02d:%02d:%02d - {%s}" fullword wide
      $s7 = "ouemm/emm!!!!!!!!!!!!!" fullword ascii
      $s8 = "Vtfs43/emm" fullword ascii 
      $s9 = "bewbqj43/emm" fullword ascii
      $s10 = "lfsofm43/emm" fullword ascii
      $s11 = "Tifmm43/emm" fullword ascii
      $s12 = "iuuqt;00????????" fullword ascii /* Encoded URL */
      $s13 = "image/jpeg" fullword wide
      $s14 = "https://en.wikipnet/search.php" fullword ascii /* legit site used as test for connectivity*/
   condition:
      uint16(0) == 0x5a4d and filesize < 70KB and ( pe.imphash() == "c71a34b50e03311fe548bb5a730e97ac" and ( pe.exports("JLI_AcceptableRelease") and pe.exports("JLI_ExactVersionId") and pe.exports("JLI_FreeManifest") and pe.exports("JLI_JarUnpackFile") and pe.exports("JLI_MemFree") and pe.exports("JLI_MemRealloc") ) and 12 of them
}

rule Mal_BozokRAT_July2020_2 {
   meta:
      description = "Detect BozokRAT used by APT Patchwork in July 2020"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/tree/master/Indian/APT/Patchwork/2020-07-23/Analysis.md"
      date = "2020-07-15"
      hash1 = "cc8867a5fd62b82e817afc405807f88716960af5744040999b619b126a9ecf57"
   strings:
      $s1 = "ouemm/emm!!!!!!!!!!!!!" fullword ascii
      $s2 = "Vtfs43/emm"  fullword ascii 
      $s3 = "lfsofm43/emm" fullword ascii
      $s4 = "bewbqj43/emm" fullword ascii
      $s5 = "Tifmm43/emm" fullword ascii
      $s6 = "bitdefender_isecurity.exe" fullword ascii
      $s7 = "MwTqjwfUjqwvboNfnlqz" fullword ascii /* Xor 0x3  -> NtWriteVirtualMemory */
      $s8 = "P}_dgkz\\co}ElYoi~ced " fullword ascii /* Xor 0xA  -> ZwUnmapVViewOfSection */
      $s9 = "gy|ix;;:$nff" fullword ascii /* Xor 0xA  -> msvcr110.dll */ 
      $s10 = "ybf}kzc$nff" fullword ascii /* Xor 0xA  -> shlwapi.dll */  
      $s11 = "Tray.exe" fullword ascii
      $s12 = "InternetCheckConnectionA" fullword ascii
      $s13 = "--*****------" fullword ascii
      $s14 = "https://en.wikipedia.org/wiki/Main_Page" fullword ascii /* legit site used as test for connectivity*/
   condition:
      uint16(0) == 0x5a4d and filesize < 130KB and ( pe.imphash() == "79cf8ca8dd4dad9d47e49beb5c9bbd50" or 11 of them )
}
