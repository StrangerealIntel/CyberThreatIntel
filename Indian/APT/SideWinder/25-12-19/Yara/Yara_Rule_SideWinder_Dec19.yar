/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_SideWinder_LNK_Dec19_1 {
   meta:
      description = "Detect LNK file used by APT SideWinder"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md"
      date = "2019-12-28"
      hash1 = "957a7b669d73ed4219fca89ebc5d49739f530f6df5828ef48bec900bd132ff9b"
   strings:
      $s1 = "@shell32.dll,-21769" fullword wide
      $s2 = "S-1-5-21-1302019708-1500728564-335382590-1000" fullword wide
      $s3 = "@shell32.dll,-21813" fullword wide
      $s4 = "[..\\..\\..\\..\\..\\Desktop\\" fullword wide
      $s5 = ".rtf" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 3KB and all of them
}

rule APT_SideWinder_RTF_Dec19_1 {
   meta:
      description = "Detect RTF file used by APT SideWinder"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md"
      date = "2019-12-28"
      hash1 = "87882b884afd4bd6d4da1fb5e3f87d728f128f75fae32a2720fe899ac7f23f5d"
   strings:
      $s1 = "\\par 5.\\tab }{\\rtlch\\fcs1 \\af1 \\ltrch\\fcs0 \\insrsid6948592 Command and Operational Authorities are to ensure that these " ascii
      $s3 = "2b39423552767779557174752f545941752f6f2b3937534874785179466546702b7456546f616659366975774b344c4b4730483273736e4b584c39367751637a" ascii /* hex encoded string '+9B5RvwyUqtu/TYAu/o+97SHtxQyFeFp+tVToafY6iuwK4LKG0H2ssnKXL96wQcz' */
      $s4 = "2f2b563762424544636c4137522b74427339495574346c646267482f452b70544d542f68694f4c446c2b416b634f3438594c736b47756f6c6672505669747679" ascii /* hex encoded string '/+V7bBEDclA7R+tBs9IUt4ldbgH/E+pTMT/hiOLDl+AkcO48YLskGuolfrPVitvy' */
      $s5 = "793431527173426e6a334f2b545653415030466b3367727546414b766a6f456f3643714944526d6d41565658506a4d7a4d4959534776475753536c7752727a44" ascii /* hex encoded string 'y41RqsBnj3O+TVSAP0Fk3gruFAKvjoEo6CqIDRmmAVVXPjMzMIYSGvGWSSlwRrzD' */
      $s6 = "72344e4d37597845526356334f4872492f4846647a34552f4253545965683830593365724830634b506c5a67514e6e71446d59523745336b7263745230364c53" ascii /* hex encoded string 'r4NM7YxERcV3OHrI/HFdz4U/BSTYeh80Y3erH0cKPlZgQNnqDmYR7E3krctR06LS' */
      $s7 = "576b54384269765a36634265734a5a4545676c6e5a546f6f565436637a32445332434d64715643434f6c434b2b71554759486e643978744c58574d6f52484a47" ascii /* hex encoded string 'WkT8BivZ6cBesJZEEglnZTooVT6cz2DS2CMdqVCCOlCK+qUGYHnd9xtLXWMoRHJG' */
      $s8 = "656c6470615332446b4f39484e64356b6870722f616b5861386c47347875326d444972696d474e744d43355a3835735536767a57397a696b775a62305363786b" ascii /* hex encoded string 'eldpaS2DkO9HNd5khpr/akXa8lG4xu2mDIrimGNtMC5Z85sU6vzW9zikwZb0Scxk' */
      $s9 = "746e374d436b31444a6431653771374770765237563531314861534a5338517777647058342b4f322b7244722f56356f666d772b757739517a66426d54667a6a" ascii /* hex encoded string 'tn7MCk1DJd1e7q7GpvR7V511HaSJS8QwwdpX4+O2+rDr/V5ofmw+uw9QzfBmTfzj' */
      $s10 = "57593936453835772f7a6e7566583243576e303249307a7073326e625a476d4e5436654e497348327032373144785061505a503650692b375147664470514e7a" ascii /* hex encoded string 'WY96E85w/znufX2CWn02I0zps2nbZGmNT6eNIsH2p271DxPaPZP6Pi+7QGfDpQNz' */
      $s11 = "76346a397238507171377934514b347651686e474a63376a4163554a524c4e4e3949676a783052516c315636694b70594d41586c474e436b572f484771313568" ascii /* hex encoded string 'v4j9r8Pqq7y4QK4vQhnGJc7jAcUJRLNN9Igjx0RQl1V6iKpYMAXlGNCkW/HGq15h' */
      $s12 = "774e76796337327a46416974387766625a6a4e4e72724a2f50355934376a5665515a55634178795046526644365a343068476e744b50322b63366c6944503738" ascii /* hex encoded string 'wNvyc72zFAit8wfbZjNNrrJ/P5Y47jVeQZUcAxyPFRfD6Z40hGntKP2+c6liDP78' */
      $s13 = "3057366354307a5a69452b6559576554474e7a55393236472b64374e412f75396b336d557a362f75736a3036685a4941587a2b5a6a5042337765374763336565" ascii /* hex encoded string '0W6cT0zZiE+eYWeTGNzU926G+d7NA/u9k3mUz6/usj06hZIAXz+ZjPB3we7Gc3ee' */
      $s14 = "656e74323d22616363656e74322220616363656e74333d22616363656e74332220616363656e74343d22616363656e74342220616363656e74353d2261636365" ascii /* hex encoded string 'ent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>' */
      $s15 = "4355786a666f6475623833714f6c6b43423367684572346d524f5152426e6c486471424865352f416e6c74654642736a727a4a2f504f483837635344707a374c" ascii /* hex encoded string 'CUxjfodub83qOlkCB3ghEr4mROQRBnlHdqBHe5/AnlteFBsjrzJ/POH87cSDpz7L' */
      $s16 = "46513941517a5164646d4b77713661335a7a444866594336306c70484d56674f45494f6d5137374a55576579583238745449347549736b336d6b315434387a32" ascii /* hex encoded string 'FQ9AQzQddmKwq6a3ZzDHfYC60lpHMVgOEIOmQ77JUWeyX28tTI4uIsk3mk1T48z2' */
      $s17 = "41546d683864756a52315036673030324d72704f79424f4575557572426443555951444f5677615a7447594454673376365766334e494f734d6f4c66657a7571" ascii /* hex encoded string 'ATmh8dujR1P6g002MrpOyBOEuUurBdCUYQDOVwaZtGYDTg3v6Wf3NIOsMoLfezuq' */
      $s18 = "333662544c4f743272576e354e78766839562f306a472b583555766642394e4d37666f2b6e6c7944682f6a3659376b33482b486f76656c497a7a39316a30546d" ascii /* hex encoded string '36bTLOt2rWn5Nxvh9V/0jG+X5UvfB9NM7fo+nlyDh/j6Y7k3H+HovelIzz91j0Tm' */
      $s19 = "382b394d79702f514f6e502f6e4f5030682b6164562f2b736f722f33627a667a6a35796c2f6538612f2f356b38472f2b57662f626e3953722f782f4276326975" ascii /* hex encoded string '8+9Myp/QOnP/nOP0h+adV/+sor/3bzfzj5yl/e8a//5k8G/+Wf/bn9Sr/x/Bv2iu' */
      $s20 = "39336e486c627250655a7738307456722b3649366a6577775a466a653841387032583934783952785075583934616839706e62724d504c5a543937686d4f7078" ascii /* hex encoded string '93nHlbrPeZw80tVr+6I6jewwZFje8A8p2X94x9RxPuX94ah9pnbrMPLZT97hmOpx' */
   condition:
      uint16(0) == 0x5c7b and filesize < 5000KB and 8 of them
}

rule APT_SideWinder_NET_Loader_Dec19_1 {
   meta:
      description = "Detect .NET loader file used by APT SideWinder"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md"
      date = "2019-12-28"
      hash1 = "e8910fc0736187889b27011848baf12ffbc306aa2fcb487451cab5af58d96c62"
   strings:
      $s1 = "\\DUSER.dll" fullword ascii
      $s2 = ".tmp          " fullword wide
      $s3 = "FileRipper" fullword ascii
      $s4 = "pluginAssembly" fullword ascii
      $s5 = "InitGadgets" fullword ascii
      $s6 = "Start" fullword ascii
      $s7 = "Program" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and ( pe.exports("FileRipper") or all of them )
}

rule APT_SideWinder_JS_Dec19_1 {
   meta:
      description = "Detect JS script file used by APT SideWinder"
      author = "Arkbird_SOLG"
      reference = "https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Indian/APT/SideWinder/25-12-19/analysis.md"
      date = "2019-12-28"
      hash1 = "c733dba9451c632c19aaad8d1de61e905dac88453b0839e8900777e121de1755"
   strings:
      $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXY"
      $s2 = "Zabcdefghijklmnopqrstuvwxyz0123456789+/=" ascii
      $s3 = "window.resizeTo(1, 1)" ascii 
      $s4 = "window.moveTo(-1000, -1200)" ascii 
      $s5 = "new Enumerator(" ascii 
      $s6 = "](x,y" ascii 
      $s7 = "finally{window.close();}" ascii 
      $s8 = "^ key." ascii
      $s9 = ".GetFolder(" ascii
      $s10 = ".Environment(" ascii
      $s11 = "(key, bytes){" ascii
      $s12 = "TransformFinalBlock(" ascii
      $s13 = "GetByteCount_2(" ascii
      $s14 = "GetBytes_4(" ascii
      $s15 = "ActiveXObject;" ascii
      $s16 = "String.fromCharCode;" ascii
      $s17 = ".join("")" ascii
      $s18 = ".Position = 0;" ascii
      $s19 = ".charCodeAt(" ascii
      $s20 = "& 255" ascii
      $s21 = ".charAt(" ascii 
      $s22 = ".GetSpecialFolder(" ascii
      $s23 = ".atEnd() == false)" ascii
   condition:
      uint16(0) == 0x090a and filesize < 3000KB and all of them
}
