import "pe"

rule Mal_MoriAgent_June_2020_1 {
   meta:
      description = "Detect MoriAgent malware (June 2020)"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/tree/master/Iran/APT/Muddywater/2020-07-02/Analysis.md"
      date = "2020-07-02"
      hash1 = "72f487068c704b6d636ddd87990e25ce8cd5940244e581063f4c54afa4438212"
      hash2 = "92cb75c15da69fd6ef9368c03fd5001778d5fa1f7b024d63c84c13f501d5acd5"
      hash3 = "7408075bbf433da260d2823213ddde1b2d47b5c89419bab4c6f1480f9d7976c8" 
   strings:
      $s1 = "Host: " fullword ascii
      $s2 = "host unreachable" fullword ascii
      $s3 = "ReflectiveLoader" fullword ascii
      $s4 = "ShellExecuteA" fullword ascii
      $s5 = "operator<=>" fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = "Content-Type: application/json\r\n" fullword ascii 
      $s8 = "Token: " fullword ascii
      $s9 = "File Access Transfer Field" fullword ascii
      $s10 = "WinHttpGetIEProxyConfigForCurrentUser" fullword ascii
      $s11 = ".pdf"fullword ascii
      $s12 = "Port" fullword ascii
      $s13 = "Domain" fullword wide
      $s14 = "HTTP/1.1\r\n" fullword ascii
      $s15 = "Transfer-Encoding" fullword ascii
      $s16 = "Content-Length" fullword ascii
      $s17 = "_VERSION_INFO" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (pe.imphash() == "7675f471383189358ce7a96a307693b0" or pe.imphash() == "625815b34998001fcf431881c99e191c"  or 14 of them )
}

rule Mal_MoriAgent_January_2020_1 {
   meta:
      description = "Detect MoriAgent malware (January 2020)"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/tree/master/Iran/APT/Muddywater/2020-07-02/Analysis.md"
      date = "2020-07-02"
      hash1 = "84809eff629da3722a181a19f52c4c27e8355b6b916c367212085743c06cfcea"
      hash2 = "ed23566a10b372028d3a275a8332ef76754976848c9357a66d1a9c320b131092"     
   strings:
      $s1 = "Host: " fullword ascii
      $s2 = "host unreachable" fullword ascii
      $s3 = "DllRegisterServer" fullword ascii
      $s4 = ".old" fullword ascii
      $s5 = "Content-Length: " fullword ascii
      $s6 = "operator co_await" fullword ascii
      $s7 = "Content-Type: application/json\r\n" fullword ascii 
      $s8 = "Unable to parse token length" fullword ascii
      $s9 = { 6d 00 69 00 6e 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 5c 00 63 00 72 00 74 00 73 00 5c 00 75 00 63 00 72 00 74 00 5c 00 69 00 6e 00 63 00 5c 00 63 00 6f 00 72 00 65 00 63 00 72 00 74 00 5f 00 69 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 5f 00 73 00 74 00 72 00 74 00 6f 00 78 00 2e 00 68 } /* minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h */
      $s10 = "WinHttpGetIEProxyConfigForCurrentUser" fullword ascii
      $s11 = "SOfTWARE\\NFC\\"fullword ascii
      $s12 = "Port" fullword ascii
      $s13 = "Domain" fullword wide
      $s14 = "HTTP/1.1\r\n" fullword ascii
      $s15 = "Transfer-Encoding" fullword ascii
      $s16 = { 49 6e 66 6f 00 00 00 00 3f 69 3d 00 43 3a 5c 00 53 79 73 74 65 6d 44 72 69 76 65 00 5c 00 00 00 49 64 } /* Info?i=C:\\SystemDrive\\Id */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (pe.imphash() == "3bcc46e3f517ddf9666020895796153f" or 14 of them )
