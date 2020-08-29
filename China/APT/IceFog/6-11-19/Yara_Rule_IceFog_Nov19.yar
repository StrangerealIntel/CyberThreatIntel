import "pe"

rule APT_IceFog_dll_Nov19_1 {
   meta:
      description = "337c45cd1a9395097e6d8ebc44dd22d9fb7c6bde25ca8956fcf3e09eaf31797c.dll"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/securitydoggo/status/1192073306255560704"
      date = "2019-12-14"
      hash1 = "337c45cd1a9395097e6d8ebc44dd22d9fb7c6bde25ca8956fcf3e09eaf31797c"
   strings:
      $x1 = "c:\\Users\\john\\Documents\\Visual Studio 2008\\Projects\\vpnet_dll\\Release\\vpnet_dll.pdb" fullword ascii
      $s2 = "rundll32.exe %s startwork" fullword ascii
      $s3 = "vpnet_dll.dll" fullword ascii
      $s4 = "www.123456abcgsdwere56463455345435435657222222.com" fullword ascii
      $s5 = "%sadcache.dll" fullword wide
      $s6 = "Calling gethostbyname with %s" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "startwork" fullword ascii
      $s9 = "VirtualAlloc failed!" fullword ascii
      $s10 = "WSAStartup failed: %d" fullword ascii
      $s11 = "KQ? =0VNVIA[+" fullword ascii
      $s12 = "yMHB\\)B\\ECG{X}E" fullword ascii
      $s13 = "Rich4_M" fullword ascii
      $s14 = "URPQQh|]" fullword ascii
      $s15  = "This indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native" ascii
   condition:
      uint16(0) == 0x5a4d and filesize > 200KB and
      ( pe.imphash() == "cbc902098f5bd92d34971b49ccd07e0f" and pe.exports("startwork") or ( 1 of ($x*) or 4 of them ) )
}

rule APT_IceFog_Maldoc_Nov19_1 {
   meta:
      description = "vietlao.rtf"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/securitydoggo/status/1192073306255560704"
      date = "2019-12-14"
      hash1 = "c2ea07a400fb89b8f0f9551caa1e27599a4e4b94fde646f167c9e527e19d0fa7"
   strings:
      $x1 = "{\\rtf1 \\ansi \\ansicpg936 \\deff0 \\stshfdbch2 \\stshfloch2 \\stshfhich2 \\deflang2052 \\deflangfe2052 {\\fonttbl {\\f0 \\from" ascii
      $s2 = "00000043003A005C00550073006500720073005C00410044004D0049004E0049007E0031005C0041007000700044006100740061005C004C006F00630061006C" ascii /* hex encoded string 'C:\Users\ADMINI~1\AppData\Local\Temp\8.t' */
      $s3 = "4d61746854797065" ascii /* hex encoded string 'MathType' */
      $s4 = "00433A5C55736572735C41444D494E497E315C417070446174615C4C6F63616C5C54656D705C382E74" ascii /* hex encoded string 'C:\Users\ADMINI~1\AppData\Local\Temp\8.t' */
      $s5 = "433A5C4161615C746D705C382E74" ascii /* hex encoded string 'C:\Aaa\tmp\8.t' */
      $s6 = "4571756174696f6e2e32" ascii /* hex encoded string 'Equation.2' */
      $s7 = "433A5C55736572735C41444D494E497E315C417070446174615C4C6F63616C5C54656D705C382E74" ascii /* hex encoded string 'C:\Users\ADMINI~1\AppData\Local\Temp\8.t' */
      $s8 = "005061636B616765" ascii /* hex encoded string 'Package' */
      $s9 = "4d45544146494c4550494354" ascii /* hex encoded string 'METAFILEPICT' */
      $s10 = "5061636B616765" ascii /* hex encoded string 'Package' */
      $s11 = "00000043003A005C004100610061005C0074006D0070005C0038002E0074" ascii /* hex encoded string 'C:\Aaa\tmp\8.t' */
      $s12 = "\\u224 ?o - Trung Qu\\uc1 \\u7889 ?c t\\uc1 \\u7841 ?i \\uc1 \\u273 ?\\uc1 \\u7881 ?nh Khoan La San; \\uc1 \\u273 ?\\uc1 \\u7871" ascii
      $s13 = "889 ?c bi\\uc1 \\u234 ?n gi\\uc1 \\u7899 ?i \\uc1 \\u273 ?\\uc1 \\u7845 ?t li\\uc1 \\u7873 ?n Vi\\uc1 \\u7879 ?t Nam - Trung Qu" ascii
      $s14 = "24 ?o - Trung Qu\\uc1 \\u7889 ?c; v\\uc1 \\u224 ? ng\\uc1 \\u224 ?y }{\\fs28 \\rtlch \\alang1025 \\ltrch \\dbch \\af2 \\hich \\a" ascii
      $s15 = "u224 ?o - Trung Qu\\uc1 \\u7889 ?c k\\uc1 \\u253 ? }{\\fs28 \\rtlch \\alang1025 \\ltrch \\dbch \\af2 \\hich \\af0 \\loch \\f0 " ascii
      $s16 = "224 ?o - Trung Qu\\uc1 \\u7889 ?c \\uc1 \\u273 ?\\uc1 \\u227 ? \\uc1 \\u273 ?\\uc1 \\u432 ?\\uc1 \\u7907 ?c x\\uc1 \\u225 ?c \\u" ascii
      $s17 = "uc1 \\u432 ?\\uc1 \\u7899 ?c Vi\\uc1 \\u7879 ?t Nam - L\\uc1 \\u224 ?o - Trung Qu\\uc1 \\u7889 ?c n\\uc1 \\u259 ?m 2006 v\\uc1 " ascii
      $s18 = "34 ?n gi\\uc1 \\u7899 ?i Vi\\uc1 \\u7879 ?t Nam - L\\uc1 \\u224 ?o, Vi\\uc1 \\u7879 ?t Nam - Trung Qu\\uc1 \\u7889 ?c v\\uc1 \\u" ascii
      $s19 = "u227 ? ba bi\\uc1 \\u234 ?n gi\\uc1 \\u7899 ?i Vi\\uc1 \\u7879 ?t Nam - L\\uc1 \\u224 ?o - Trung Qu\\uc1 \\u7889 ?c, t\\uc1 \\u7" ascii
      $s20 = "\\alang1025 \\ltrch \\dbch \\af2 \\hich \\af0 \\loch \\f0 \\lang1066 \\langnp1066 \\langfe1033 \\langfenp1033 - }{\\i1 \\fs28 " ascii
   condition:
      uint16(0) == 0x5c7b and filesize > 1000KB and
      1 of ($x*) and 4 of them
}
