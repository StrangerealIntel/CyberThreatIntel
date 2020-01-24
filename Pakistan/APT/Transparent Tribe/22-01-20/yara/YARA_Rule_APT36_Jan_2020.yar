import "pe"

rule APT_Transparent_Tribe_NET_PE_Jan20_1 {
   meta:
      description = "Detect .NET PE file used by APT Transparent_Tribe"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Pakistan/APT/Transparent%20Tribe/22-01-20/analysis.md"
      date = "2020-01-24"
      hash1 = "d2c46e066ff7802cecfcb7cf3bab16e63827c326b051dc61452b896a673a6e67"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "ulhtagnias.exe" fullword wide
      $s3 = "g:\\ulhtagnias\\ulhtagnias\\obj\\Debug\\ulhtagnias.pdb" fullword ascii
      $s4 = "ulhtagniasdo_process" fullword ascii
      $s5 = "ulhtagniaslist_processes" fullword ascii
      $s6 = "ulhtagnias-procl=process|ulhtagnias" fullword wide
      $s7 = "ulhtagniasget_command" fullword ascii
      $s8 = "ulhtagniasport" fullword ascii
      $s9 = "tempStr" fullword ascii
      $s10 = "ulhtagniasatmps" fullword ascii
      $s11 = ".exe|ulhtagnias" fullword wide
      $s12 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|ulhtagnias" fullword wide
      $s13 = "$recycle.bin|ulhtagnias" fullword wide
      $s14 = "get_very_sold" fullword ascii
      $s15 = "documents and settings|ulhtagnias" fullword wide
      $s16 = "bdss=Bit Defender,onlinent=Q.Heal,bdagent=Bit Defender Agent,msseces=MS Essentials,fssm32=FSecure,avp=Kaspersky,avgnt=Avira,spbb" ascii
      $s17 = "getByteArray" fullword ascii
      $s18 = "ulhtagniasfilesLogs" fullword ascii
      $s19 = "122.200.110.101|ulhtagnias" fullword wide
      $s20 = "ulhtagniasget_size" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

rule APT_Transparent_Tribe_Maldoc_Jan20_1 {
   meta:
      description = "Detect maldoc file used by APT Transparent_Tribe"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Pakistan/APT/Transparent%20Tribe/22-01-20/analysis.md"
      date = "2020-01-24"
      hash1 = "2aa160726037e80384672e89968ab4d2bd3b7f5ca3dfa1b9c1ecc4d1647a63f0"
      hash2 = "1cb726eab6f36af73e6b0ed97223d8f063f8209d2c25bed39f010b4043b2b8a1"
   strings:
      $x1 = "*\\G{D1C702E6-4518-48EB-AFC3-58BFFDB8BB9D}#2.0#0#C:\\Users\\Bipin\\AppData\\Local\\Temp\\VBE\\MSForms.exd#Microsoft Forms 2.0 Ob" wide
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.4#0#C:\\Program Files (x86)\\Common Files\\Microsoft Shared\\OFFICE12\\MSO.DLL#Micr" wide
      $s3 = "*\\G{0D452EE1-E08F-101A-852E-02608C4D0BB4}#2.0#0#C:\\Windows\\SysWOW64\\FM20.DLL#Microsoft Forms 2.0 Object Library" fullword wide
      $s4 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.0#9#C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA6\\VBE6.DLL#Visual Basic For Applicat" wide
      $s5 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\SysWOW64\\stdole2.tlb#OLE Automation" fullword wide
      $s6 = "\\AppData" fullword ascii
      $s7 = "Shell.Application" fullword ascii
      $s8 = "UserForm1" fullword wide
      $s9 = "Begin {C62A69F0-16DC-11CE-9E98-00AA00574A4F} UserForm1 " fullword ascii
      $s10 = "VERSION 5.00" fullword ascii
      $s11 = "UserForm1=0, 0, 0, 0, C, 52, 52, 1454, 685, C" fullword ascii
      $s12 = "VBFrame" fullword wide
      $s13 = "1UserForm1" fullword wide
      $s14 = "UserForm1)" fullword ascii
      $s15 = "ShellV" fullword ascii
      $s16 = "Module1" fullword wide
      $s17 = "TextBox2" fullword ascii
      $s18 = "TextBox1" fullword ascii
      $s19 = "Project1" fullword ascii
      $s20 = "zip_Mofer_file" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 1000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}
