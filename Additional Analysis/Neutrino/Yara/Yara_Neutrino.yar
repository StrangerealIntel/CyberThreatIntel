/*
   YARA Rule Set
   Author: Arkbird SOLG
   Date: 2020-02-13 
   Reference: https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Neutrino/Analysis_2020-02-08.md
*/

import "pe"

rule Dropper_Neutrino_Feb_20 {
   meta:
      description = "Detect the dropper used by Neutrino"
      author = "Arkbird SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Neutrino/Analysis_2020-02-08.md"
      date = "2020-02-13"
      hash1 = "c0355c2a7241cb9f764297cf4e7e758116c82db35f909cf18091ec2085fe23ce"
   strings:
      $s1 = "@\\*.exe" fullword wide
      $s2 = "process call create %s" fullword wide
      $s3 = " /a /c %s" fullword wide
      $s4 = "netsh firewall add allowedprogram \"%s\" %s ENABLE" fullword wide
      $s5 = "netsh advfirewall firewall add rule name=\"%s\" dir=in action=allow program=\"%s\"" fullword wide
      $s6 = "QSSSSSSWS" fullword ascii
      $s7 = "+ :_`3" fullword ascii
      $s8 = "z`fFbffafVcfv`" fullword ascii
      $s9 = "mQWD5Wt" fullword ascii
      $s10 = "XjkYjaf" fullword ascii
      $s11 = "QQSVWhu" fullword ascii
      $s12 = "WFxbH|`" fullword ascii
      $s13 = "SVWjQXjmYjdf" fullword ascii
      $s14 = "VWjQXjMf" fullword ascii
      $s15 = "-QTUCTu@" fullword ascii
      $s16 = "XjmZjnf" fullword ascii
      $s17 = "VWjQXjmYjdf" fullword ascii
      $s18 = "VjQXjMf" fullword ascii
      $s19 = "x`FDbFdaFTcF^" fullword ascii
      $s20 = "jdXj2YC" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 300KB and
      ( pe.imphash() == "934381a85d55af4033da1a769f2cce1d" or 8 of them )
}
