rule APT_Kimsuky_PyRecon_Mar2020_1 {
   meta:
      description = "Detect the Python implant used by Kimsuky group by strings"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Kimsuky/2020-03-20/Analysis.md"
      date = "2020-03-20"
      hash1 = "7f83912127f5b9680ff57581fc40123c21257bd8e186d7cab4c838a867bb137f"
   strings:
      $s1 = "posixpath.expandvars(" fullword ascii
      $s2 = "Group Containers" fullword ascii
      $s3 = "zippass" fullword ascii
      $s4 = "exec(urllib2.urlopen(urllib2.Request(" fullword ascii
      $s5 = "target=SpyLoop" fullword ascii
      $s6 = "boundary=----7e222d1d50232" fullword ascii      
   condition:
        4 of them 
}

rule APT_Kimsuky_PowerRecon_Mar2020_1 {
   meta:
      description = "Detect the Powershell implant used by Kimsuky group by strings"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/North%20Korea/APT/Kimsuky/2020-03-20/Analysis.md"
      date = "2020-03-20"
      hash1 = "828a5527e25e3cab4e97ed25ec2b3d2d7cdf22f868101a33802598cc974d6db4"
   strings:
      $s1 = "UpLoad Success!!!" fullword ascii
      $s2 = "Alzipupdate" fullword ascii
      $s3 = "post.php" fullword ascii
      $s4 = "rundll32.exe" fullword ascii
      $s5 = "[Environment]::GetFolderPath("Recent")" fullword ascii
      $s6 = "----WebKitFormBoundarywhpFxMBe19cSjFnG" fullword ascii   
      $s7 = "?filename=" fullword ascii 
      $s8 = "del.php" fullword ascii    
   condition:
        6 of them 
}
