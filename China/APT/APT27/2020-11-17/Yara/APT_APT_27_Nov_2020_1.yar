rule APT_APT_27_Nov_2020_1 { 
 meta: 
    description = "Detect APT27 ELF rootkit" 
    author = "Arkbird_SOLG"
    reference = "Internal Research"
    date = "2020-11-16"
    hash1 = "08f29e234f0ce3bded1771d702f8b5963b144141727e48b8a0594f58317aac75"
    hash2 = "225c4f945e7f1d8296253654921c474e90829036ea0b4797ebbc9364604bf334"
    hash3 = "6a9f16440b9319f427825bb12d7a0cda89b101cf7b8b15ec7dd620b4d68db514"
    hash4 = "7de86f83f18c6c8ded0d75ab2f84f34ab115dd84d36b7e490e2bd456f77a78ce"
    hash5 = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
 strings:
      $s1 = "bypass_iptables" fullword ascii
      $s2 = "PortforwardThread" fullword ascii
      $s3 = "getfiles" fullword ascii
      $s4 = "<LIST><name><![CDATA[%s]]></name><type>%o</type><perm>%o</perm><user>%s:%s</user><size>%llu</size><time>%s</time></LIST>" fullword ascii
      $s5 = "portforward.c" fullword ascii
      $s6 = "LOGNAME=root" fullword ascii
      $s7 = "xorkeys" fullword ascii
      $s8 = "USERNAME=root" fullword ascii
      $s9 = "PortMapThread" fullword ascii
      $s10 = "USER=root" fullword ascii
      $s11 = "encrypt_pty" fullword ascii
      $s12 = "encrypt_code" fullword ascii
      $s13 = "DownFile" fullword ascii
      $s14 = "get_randstr" fullword ascii
      $s15 = "PtyShell" fullword ascii
      $s16 = "encrypt.c" fullword ascii
      $s17 = "ReConnect" fullword ascii
      $s18 = "saferecv" fullword ascii
      $s19 = "sendudp" fullword ascii
      $s20 = "safesend" fullword ascii
 condition: 
    uint16(0) == 0x7f45 and filesize > 25KB and 12 of ($s*) 
}
