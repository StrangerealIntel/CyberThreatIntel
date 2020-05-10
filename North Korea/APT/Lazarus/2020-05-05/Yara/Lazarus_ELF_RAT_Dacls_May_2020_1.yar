rule Lazarus_ELF_Dacls_May_2020_1 {
   meta:
      description = "Detect ELF RAT Dacls by the strings (May 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/philofishal/status/1257669351899086849"
      date = "2020-05-10"
      hash1 = "846d8647d27a0d729df40b13a644f3bffdc95f6d0e600f2195c85628d59f1dc6" /* SubMenu.nib */
   strings:
      $s1 = "rc4_cryptP9_CMataNetP9rc4_statePKhPhi" fullword ascii
      $s2 = "c_2910.cls" fullword ascii
      $s3 = "k_3872.cls" fullword ascii
      $s4 = "plugin_" fullword ascii
      $s5 = "/Library/Caches/com.apple.appstore.db" fullword ascii
      $s6 = "/proc/%d/cmdline" fullword ascii
      $s7 = "/proc/%d/status" fullword ascii
      $s8 = "/proc/%d/task" fullword ascii
      $s9 = "SCAN\\t%s\\t%d.%d.%d.%d\\t%d\\n" fullword ascii
      $s10 = "start_worm_scan" fullword ascii
      $s11 = "GetConfigFilename" fullword ascii
      $s12 = "Host: %s\\r\\n" fullword ascii
      $s13 = "Certificate:\\n" fullword ascii
   condition:
       (uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca)
 and filesize > 250KB and 10 of them
}
