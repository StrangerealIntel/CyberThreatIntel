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
     $s1 = "PortforwardThread" fullword ascii
     $s2 = "bypass_iptables" fullword ascii
     $s3 = "gethostbyname@@GLIBC_2.2.5" fullword ascii
     $s4 = "getfiles" fullword ascii
     $s5 = "<LIST><name><![CDATA[%s]]></name><type>%o</type><perm>%o</perm><user>%s:%s</user><size>%llu</size><time>%s</time></LIST>" fullword ascii
     $s6 = "portforward.c" fullword ascii
     $s7 = "execve@@GLIBC_2.2.5" fullword ascii
     $s8 = "LOGNAME=root" fullword ascii
     $s9 = "xorkeys" fullword ascii
     $s10 = "PortMapThread" fullword ascii
     $s11 = "USER=root" fullword ascii
     $s12 = "USERNAME=root" fullword ascii
     $s13 = "getpid@@GLIBC_2.2.5" fullword ascii
     $s14 = "encrypt.c" fullword ascii
     $s15 = "DownFile" fullword ascii
     $s16 = "fgets@@GLIBC_2.2.5" fullword ascii
     $s17 = "encrypt_pty" fullword ascii
     $s18 = "getgrgid@@GLIBC_2.2.5" fullword ascii
     $s19 = "ReConnect" fullword ascii
     $s20 = "getsockopt@@GLIBC_2.2.5" fullword ascii
 condition: 
    uint16(0) == 0x457f and filesize > 20KB and 12 of them 
}
