rule APT_APT33_VBE_Malware_Nov19_1{
   meta:
      description = "JobDescription.vbe"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/APT33/16-11-19/Analysis%20APT33.md"
      date = "2019-11-18"
      hash1 = "92e66acd62dfb1632f6e4ccb90a343cb8b8e2f4fb7c9bfa9ae0745db0748223b"
   strings:
      $s1 = "5YxJ:dFcHjC,JGo5!oQ-3&Q 3n&I_{JNfS&q}!*;Wf2yOAyoGw&XboElf*EbY[qb1nR&:S0yTT&0^YSj00-dll&?_s%" fullword ascii
      $s2 = ":Trx}\"FxpyfPH*+ b0?(" fullword ascii
      $s3 = "xD+.PK/,* !p~Rg2P~;SI~qcF c2+yi~c1AKP;S\"~&c* &ZG+1pPRg3K,ZS\"~fRZR2!" fullword ascii
      $s4 = "xY04Aq(y4T%\"wWw6w$kzXT:}E$15(Aaq4bDB+X -X038f9\\p5s:8vX6IzCWkx!B[VGkq.WW06sJaFotto(tiohwto6d6Tl$X^ vU[Dp$fG\"T6sm }N61|38+hk{G1" ascii
      $s5 = "Ssfo1(a4_ZHC1y#!nt+jbLzHc0B+rw{f\\L^.STyqTGm}lY^bF954st;wn/dbIMgd+I_!`!A.z&1\\QKpCs(W}GjrxHoF" ascii
      $s6 = "bx[WAd,1PP+ !pPP.bN+UOJc !p~US/;FpPRg2:~ZdI~ c! XZG FIPt+NbC~Z" fullword ascii
      $s7 = ".U+D2XwsW.nMR)wask1lOrKxJb@#@&BvP}2" fullword ascii
      $s8 = "PbML`8#@#@&~3x9P&0@#@&@#@&}x~2M.WMP!GDWPT@#@&@#@&PUnDP$UP{PZM+mO+}4%+1YcEzfrG$RUYD" fullword ascii
      $s9 = "\\l1DG@#@&2U[,?E(@#@&@#@&?!8~fKm!:nxO6a+U`*@#@&`w[CD+HC^MW@#@&AU9Pj!4@#@&@#@&?!8P`w[lD+\\C1DWvb@#@&fks~dYM~,+a+^S,hdt@#@&@#@&+an" ascii
      $s10 = "\\n.DT)loMWhAmd" fullword ascii
      $s11 = "\\l1DG@#@&2U[,?E(@#@&@#@&?!8~fKm!:nxO6a+U`*@#@&`w[CD+HC^MW@#@&AU9Pj!4@#@&@#@&?!8P`w[lD+\\C1DWvb@#@&fks~dYM~,+a+^S,hdt@#@&@#@&+an" ascii
      $s12 = "+VkHC+}o:oP}q)Z&jnF^Jo}Y6KYm&hx/f2}5[)Sbbzx'E#~](6R;Wsw.+ddbWUR;G:aDndkkWU\\KNnT=lG+^K:aD+k/*b~]Kn6DR3U1WNbUoY))zj/q&#*R]+C[:W3x" ascii
      $s13 = "YE~,EtW\"bV^lzWRZ~`1WhwmYr8^+i,\\?&2PR Ti," ascii
      $s14 = "6nm*@#@&Ax[~UE4@#@&`w[lDntl^MW@#@&R9EEAA==^#~@" fullword ascii
      $s15 = "24S}4Koo]OyLHhcIpC2hnqbNw3}LBL2qz Hdw\"He!85/[^HwTww0jM2j|2jld.+jZ7F6;2" fullword ascii
      $s16 = "t}SLyK(+|7hs;m:+Ac4XXz!H\\&$f$AZDF0?toZF" fullword ascii
      $s17 = "TV$fjR+5O&k:WqkDj0m}&4&DkFc2-}`9KPVn22#9 B}a.2SKU+!9y\";MJ.M:#EILef" fullword ascii
      $s18 = "mYvJtrmMWdW6Y ptSC:Pnr#@#@&~ok^+cr2+U~rM3KrSPrtOOa)z&+8&  y{cFXlRy*zkkDnR4YhJBPoC^/+@#@&PwkV" fullword ascii
   condition:
      uint16(0) == 0x4023 and filesize < 10KB and
      8 of them
}

rule APT_APT33_PS_Memory_Malware_Nov19_1 {
   meta:
      description = "out.ps1"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Iran/APT/APT33/16-11-19/Analysis%20APT33.md"
      date = "2019-11-18"
      hash1 = "c150736425ba05917e2768fe64decee5c257b4667eb66d55c791e70c5a477acf"
   strings:
      $s1 = "$o=\"$env:userdomain;$u;$env:computername;$env:PROCESSOR_ARCHITECTURE;$pid;https://" fullword ascii
      $s2 = "if ($h -and (($psversiontable.CLRVersion.Major -gt 2))) {$wc.Headers.Add(\"Host\",$h)}" fullword ascii
      $s3 = "$primer = (Get-Webclient -Cookie $pp).downloadstring($s)" fullword ascii
      $s4 = "} if ($cookie) { $wc.Headers.Add([System.Net.HttpRequestHeader]::Cookie, \"SessionID=$Cookie\") }" fullword ascii
      $s5 = "$wc.Headers.Add(\"User-Agent\",\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76" fullword ascii
      $s6 = "$getcreds = new-object system.management.automation.PSCredential $username,$PSS;" fullword ascii
      $s7 = "$PSS = ConvertTo-SecureString $password -AsPlainText -Force;" fullword ascii
      $s8 = "{$a.Key = [System.Convert]::FromBase64String($key)}" fullword ascii
      $s9 = "$wp.Credentials = $getcreds;" fullword ascii
      $s10 = "if ($username -and $password) {" fullword ascii
      $s11 = "if ($key.getType().Name -eq \"String\")" fullword ascii
      $s12 = "$d = (Get-Date -Format \"dd/MM/yyyy\");" fullword ascii
      $s13 = "$e = $a.CreateEncryptor()" fullword ascii
      $s14 = "$wc = New-Object System.Net.WebClient;" fullword ascii
      $s15 = "if ($IV.getType().Name -eq \"String\")" fullword ascii
      $s16 = "$wp = New-Object System.Net.WebProxy($proxyurl,$true);" fullword ascii
      $s17 = "elseif($h){$script:s=\"https://$($h)/babel-polyfill/6.3.14/\";$script:sc=\"https://$($h)\"}" fullword ascii
      $s18 = "$b = [System.Text.Encoding]::UTF8.GetBytes($un)" fullword ascii
      $s19 = "$sc=\"https://" fullword ascii
      $s20 = "$wc.Headers.Add(\"Referer\",\"\")" fullword ascii
   condition:
      uint16(0) == 0x535b and filesize < 9KB and
      8 of them
}
