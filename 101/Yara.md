# YARA
##### The following page aims to explain the basics for creating Yara rules, classification and hunting. The learning axis begins with a summary of the documentation and then on tips on everyday cases and on the approach for hunting threat actors.
## Generalities
##### To begin with it, the syntax used is close to the C language, for example, comments are ```//``` (single-line) and ```/* */``` (multi-line comment). Each rule begins by the keyword ```rule``` is identifed by their ```rule identifier``` that the title of the rule.
##### This ```identifier``` can have any alphanumeric character but must replace space by the underscore character or the first character can't be a digit and don't contains one of following reserved keywords.

<table>
    <thead>
        <tr>
            <th colspan="8" align="center">Yara keywords</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>all</td>
            <td>and</td>
            <td>any</td>
            <td>ascii</td>
            <td>at</td>
            <td>base64</td>
            <td>base64wide</td>
            <td>condition</td>
        </tr>
        <tr>
            <td>contains</td>
            <td>endswith</td>
            <td>entrypoint</td>
            <td>false</td>
            <td>filesize</td>
            <td>for</td>
            <td>fullword</td>
            <td>global</td>
        </tr>
        <tr>
            <td>import</td>
            <td>icontains</td>
            <td>iendswith</td>
            <td>in</td>
            <td>include</td>
            <td>int16</td>
            <td>int16be</td>
            <td>int32</td>
        </tr>
        <tr>
            <td>int32be</td>
            <td>int8</td>
            <td>int8be</td>
            <td>istartswith</td>
            <td>matches</td>
            <td>meta</td>
            <td>nocase</td>
            <td>not</td>
        </tr>
        <tr>
            <td>of</td>
            <td>or</td>
            <td>private</td>
            <td>rule</td>
            <td>startswith</td>
            <td>strings</td>
            <td>them</td>
            <td>true</td>
        </tr>
        <tr>
            <td>uint16</td>
            <td>uint16be</td>
            <td>uint32</td>
            <td>uint32be</td>
            <td>uint8</td>
            <td>uint8be</td>
            <td>wide</td>
            <td>xor</td>
        </tr>
    </tbody>
</table>

##### Note : Rule identifiers are case sensitive and limited to 128 characters.

##### The structure of the Yara rule is generally composed of three sections :

- ##### ```meta``` which content all the metadata of the rule
- ##### ```strings``` definition that define the strings which will be used condition part of the rule. Each one have an identifier which begin by "$" character and subject to the same rules as for rule identifier.
- ##### ```condition``` that delimits the conditions on the strings previously defined in the previous section.

```yara
rule MyRule : tags
{
    meta: 
    strings:
    condition:
}
```

## Strings
##### Three different types of string can be used in Yara : text strings, regular expressions and hexadecimal strings.

### Text stings
##### The first type of strings is text based definition. Two cases of encoding are possible ```ascii``` and ```wide``` this can have modifiers in more theirs strings declarations.

##### The text strings must have escape sequences with ```\``` like in the language C : 

<h5><table>
    <tr>
        <td>\r</td>
        <td>Carriage return</td>
    </tr>
    <tr>
        <td>\t</td>
        <td>Horizontal tab</td>
    </tr>
    <tr>
        <td>\n</td>
        <td>New line</td>
    </tr>
    <tr>
    <td>\xdd</td>
    <td>byte in hexa</td>
    </tr>
    <tr>
        <td>\"</td>
        <td>Double quote</td>
    </tr>
    <tr>
        <td>\\</td>
        <td>Backslash</td>
    </tr>
</table></h5>

##### By default, all the text strings without modifiers are defined as ascii.

#### Modifiers
##### Like said previously, a list of modifiers can be used by the analyst for improve the quality of the detection :

- ##### ```nocase``` (Case-insensitive)
##### This modifier allows to turn into case-insensitive mode (aaa = AAA) in pushing at the end of the text string. 

```
$str_ascii_nocase = "my ascii string" ascii nocase
```

##### This can be combine with any other modifier except base64 based modifier : ```base64``` and ```base64wide``` (with base 64 string, a series of different upper or lower case letters can change the result into another string than if we are just looking for the same one without a sensitive case)

- ##### ```wide```
##### This gives the possibility to parse other types of strings which are encoded with two bytes per character (\xYY\x00). For parsing it, the system will be emulate to UTF-16 strings.

```
\x45\x76\x69\x6c -> "Evil" ascii
\x45\x00\x76\x00\x69\x00\x6c\x00 -> "Evil" wide
```

- ##### ```xor```
##### In some cases, we have need to detected possibles reused strings that xored on the malicious.

##### To do this we can write to have each byte XOR applied to the string this way : 

```
$str_xor = "Evil" xor
```

##### In this way, this is equivalent to testing all possibilities from 0x0 to 0xff.

##### This possible since YARA 3.11 to specify a range of values to test as in the following example (here between 0x10 and 0xa - xor(min-max) ): 

```
$str_xor = "Evil" xor(0x10-0xa)
```

##### Note : You can test both ascii and wide in same time in using the modifiers ```ascii wide``` but don't forget that in terms of optimizations, it's better to test a value already with an xor than generated with an xor modifier.

- ##### ```fullword```
##### In the case where we need to match only when the string is fully contained and breakable.
##### By the way, this can be useful if you know that the attacker uses declination of a specifiatic and compound string.

```
$str_full = "legit" fullword
```

In this example, you can observe that the string works with ```legit-software , legit-offers ``` but not with ```mylegitoffer```.

- ##### ```base64```
##### By default, this search the first three permutations in base64 for the text string.

```
$str_b64 = "iex($payload)" base64
```

##### This possible to use a custom alphabet :

```
$str_b64 = "iex($payload)" base64("3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5")
```

##### Important : YARA strips the leading and trailing characters in the beginning and the end of the string thus a rule will be valid for strings having a common section (axxxa = cxxxc).

### Regex (Regular expressions)

##### For more flexibility in detecting an attacker's recurring pattern, it's possible to use regex with Yara. The syntax used is close to the PERL language but has some limitations with POSIX character classes and backreferences. 

<h5> In the following case, I recommend the <a href="https://regex101.com/">regex101</a> site which allows both to check the quality of our regrex and to have solid educational documentation on each element. It is also possible to use drag & drop to quickly construct and verify each regex.</h5>

<img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/101/pics/Yara/regex.png">

##### This allows the following metacharacters :

<h5><table>
<tr><td>\</td>
<td>Quote the next metacharacter</td>
</tr>
<tr><td>^</td>
<td>Match the beginning of the file</td>
</tr>
<tr><td>$</td>
<td>Match the end of the file</td>
</tr>
<tr><td>|</td>
<td>Alternation</td>
</tr>
<tr><td>()</td>
<td>Grouping</td>
</tr>
<tr><td>[]</td>
<td>Bracketed character class</td>
</tr>
</table></h5>

##### The list of the quantifiers this can be used are :

<h5><table>
<tr"><td>*</td>
<td>Match 0 or more times</td>
</tr>
<tr><td>+</td>
<td>Match 1 or more times</td>
</tr>
<tr"><td>?</td>
<td>Match 0 or 1 times</td>
</tr>
<tr><td>{n}</td>
<td>Match exactly n times</td>
</tr>
<tr"><td>{n,}</td>
<td>Match at least n times</td>
</tr>
<tr><td>{,m}</td>
<td>Match at most m times</td>
</tr>
<tr"><td>{n,m}</td>
<td>Match n to m times</td>
</tr>
</tbody>
</table></h5>

##### Note : Perl regular expressions are greedy, meaning they will match which all the data possible before a new line, using ```?``` at the end of the quantifier allows to cut as quickly as possible once the regex triggers.

##### Following escape sequence and character classes can be used in the regex : 

<h5><table>
<tr><td>\t</td>
<td>Tab (HT, TAB)</td>
</tr>
<tr><td>\n</td>
<td>New line (LF, NL)</td>
</tr>
<tr><td>\r</td>
<td>Return (CR)</td>
</tr>
<tr><td>\xnn</td>
<td>Character whose ordinal number is the given hexadecimal number</td>
</tr>
<tr><td>\w</td>
<td>Match a <em>word</em> character (alphanumeric letter)</td>
</tr>
<tr><td>\W</td>
<td>Match a <em>non-word</em> character</td>
</tr>
<tr><td>\s</td>
<td>Match a whitespace character</td>
</tr>
<tr><td>\S</td>
<td>Match a non-whitespace character</td>
</tr>
<tr><td>\d</td>
<td>Match a decimal digit character</td>
</tr>
<tr><td>\D</td>
<td>Match a non-digit character</td>
</tr>
</table></h5>

##### The regex must be declared with a couple of ```/``` like the following exemple :

```
$s = /{host : \w{3,16},os : \w{3,9}, av : [a-zA-Z]{3,32}}}/
```

### Hexadecimal sequences (traits)
##### In some cases, it's necessary to detect similiar partitions of asm codes or which may present several alternatives.

##### First, this possible to use wildcard ```?``` for specify portions of hexadecimal values that can vary and should match with anything.

##### As example, we can see that it's possible to put wildcards on part of a hex value :

```
$str_hex = { FA ?1 ?? 7? 34 }
```

##### Another highlight is the ability to jump groups of hex values in specifying the length ranges, this particularly useful for joining parts of reused codes, since the compliers each have different in terms of optimization or way of compiling the code, the opcodes will be different and as a result the hexadecimal sequences (traits) will have more or less important disparities even if we have the same original code. 

##### In this example, we can see two similiar parts of codes ```FA 21 44``` and ```77 98 34``` that have a different sequence of hex code inside, for this, we chose to specify the jump interval with the smallest and largest jump value, i.e. 2 and 4 ([min-max]).
```
FA 21 44 [2-4] 77 98 34
FA 21 44 XX XX 77 98 34
FA 21 44 YY YY YY YY 77 98 34
```

##### Note : Since YARA 2, this possible to use ```infinite``` range inno specify the min or/and max range ([-], [x-],[-y]), the parser will continue until this match on the next block of the identifier. This method is interesting the case of the attacker insert lot of spaces or junk code but this consume lot of ressources and aren't optimized in the fast approach for real time.

##### Another point of interest is the ability to switch with mutliple cases for like on a regex aproach in using  multiple jumps :
##### Here, we have an attacker which use as persistence folder a set of keywords ```ìnstall```,```word2021``` and ```excel2021``` in the ```system folder```, we can concatenate with a jump the commun part ```\xxxx2021``` ( need to have hex code in the both side of the jump, explains why use ```\```) and push the different cases in the switch state with different "OR" conditions.

<h5>

```
25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 ( 5c 69 6e 73 74 61 6c 6c | 5c [4-5] 32 30 32 31 ) 5c

-> %SystemRoot%\System32(\install|\[4-5]2021)\

That's valid for :

%SystemRoot%\System32\install\
%SystemRoot%\System32\Word2021\
%SystemRoot%\System32\Excel2021\
```
</h5>

### Condition

##### Conditions content the same syntaxe that the C# language :

- ##### The typical Boolean operators : ```and```, ```or``` and ```not```
- ##### Relational operators of comparaision : ```>=```, ```<=```, ```<```, ```>```, ```==``` and ```!=```
- ##### Arithmetic operators ```+```, ```-```, ```*```, ```\```, ```%```
- ##### Bitwise operators ```&```, ```|```, ```<<```, ```>>```, ```~```, ```^```

##### note: this is possible to check a specific count of the repetion of a sequence in push a ```#``` behind a variable like this ```#a = 10```

##### Sometimes we need to check that the location of some of the strings that the rule must detect is at these precise positions in the data stream, for this the "at" operator allows to define this location 

##### In all the examples above, the number of strings have been specified by a numeric constant, but any expression returning a numeric value can be used. The keywords ```any``` and ```all``` can be used as well.

```
all of them       // all strings in the rule
any of them       // any string in the rule
all of ($a*)      // all strings whose identifier starts by $a
any of ($a,$b,$c) // any of $a, $b or $c
1 of ($*)         // same that "any of them"
```

##### It's also possible to define where one of the conditions may be correct for the rule to work, for this we needs to set the string to a specific offset on the file or to a virtual address in the address space of the process in using the ```at``` keywork like this :

```
condition:
        $s at x 
```

##### note: this also possible to use a specific range by this time ```in``` keyword

```
$s in (x..y)
```  

<li>Filesize</li>

##### One of these special variable ```filesize``` allows the size of the file as a required condition to valid.

##### This able to support a postfix of a value of the constant of 1024 (KB,MB,GB...).

<li>Filetype</li>

#####  As for the previous case, it is also possible to use the magic numbers (onstant numerical or text value used to identify a file format or protocol) to verify that it is the correct type of file. 

##### This identifier used the unsigned integers (16 based for 2 bytes and 32 for 4 bytes) for compared to the magic number. This used the Big endian, the blocks of bytes must inversed between them (abcd -> dcba).

##### Here a list of usual identifier types of files :

|Filetype|Magic numbers|
|---|---|
|MSDOS executable|uint16(0) == 0x5a4d|
|JAR|uint32(0) == 0x04034b50|
|bmp|uint16(0) == 0x4d42|
|class|uint32(0) == 0xbebafeca|
|jpg|uint16(0) == 0xd8ff|
|Postcript|uint16(0) == 0x53502125|
|Docx/Xlsx/PPTX/Zip|uint32(0) == 0x04034b50|
|Microsoft Database|uint32(0) == 0x6e617453|
|Xls/Doc/PPT|uint32(0) == 0xe011cfd0|
|PDF|uint32(0) == 0x46445025|
|CAB Installer|uint32(0) == 0x4643534d|
|MSI|uint32(0) == 0xe011cfd0|
|RAR|uint32(0) == 0x21726152|
|EPS|uint32(0) == 0x53502125|
|SQLite Database|uint32(0) == 0x694c5153|
|Mach-O (x86)|uint32(0) == 0xcefaedfe|
|Mach-O (x64)|uint32(0) == 0xcffaedfe|
|DEX|uint32(0) == 0x0a786564|
|RTF|uint32(0) == 0x74725c7b|
|Compressed ISO image|uint32(0) == 0x215a7349|
|ISO image|uint32(0) == 0x30304443|

##### This possible to use the following recipe on cyberchef for generate your custom identifier :
https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',{2|4},true/disabled)&input={input data in base64}

### Using modules

##### The YARA core allows to load an additional modules for improve functionalities of your Yara rules.

##### The modules must be declared by the ```import``` statement before used later like this :

```
import pe
import elf
...
```

#### PE module

##### The module allows to analyze the characteristics of the PE file, the most common variables are following :

|Variable|Description|
|-------|---|
|pe.entry_point|Confer the address of the entrypoint of the PE|
|pe.sections.name|Give the section name|
|pe.number_of_sections|Give the number of sections in the PE file|
|pe.pdb_path|Path of the PDB file for this PE if its present (Yara 4.0.0)|
|pe.imphash()|Function returning the import hash or imphash for the PE file|
|pe.exports(x)|Function returning true if the PE exports match with regex, string or ordinal in the argument|
|pe.imports(x)|Function returning true if the PE imports match with regex, string or ordinal in the argument|

##### These variables allow to create conditions on a specific sections names for detect packers, pdb paths...
#### Entrypoint
##### Sometimes, it's necessary to specify conditions on the entrypoints like a specific address of a data or a pattern of data. These approaches are used for detect some patterns basically at the entrypoint to detect packers or simple file infectors.

```
rule myrule
{
    strings:
        $a = { 9c 50 66 a1 [3] 00 66 a9 [2] 58 0f 85 }
    condition:
       $a in (pe.entry_point..pe.entry_point + 100)
}
```
### Certificates

##### Sometimes, attackers can use signed binaries or script, this possible to hunt by the properties of these certifications. Here, the most common variables that can be used :

|Variable|Description|
|-------|---|
|pe.signatures.subject|Allow to search on the subject of the certificate|
|pe.signatures.issuer|Looking on the issuer field|
|pe.signatures.serial|Give the serial identifier|
|pe.number_of_signatures|Number of authenticode signatures found in the PE file|

##### For example, in the following case, the rule allow to check if one of the signatures contains a serial number of compromised certificates used by threat actors for PE files.

##### Note: Binaries can have multiple authenticode signatures, to do this we use for structure ```for any i in x :``` (similar pyhthon language)

```
import "pe"
rule CERT_APTX_Mal_Cert_Nov_2022_1 {
   meta:
      description = "Detects a compromised certificate used by the APTX"
      date = "XXXX-XX-XX"
      hash = "-"
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         // check the issuer
         pe.signatures[i].issuer contains "COMODO RSA Code Signing CA" and
            (  // Check with the list of compromissed certificates
               pe.signatures[i].serial == "1c:25:43:56:2c:2d:05:34:03:1a:77:cb:49:22:4c:cc" or 
               pe.signatures[i].serial == "4c:78:75:76:45:2d:06:15:30:98:75:ac:49:67:4d:c2"
            )
      )
}
```

### Referencing other rules

##### One of great point of Yara is the fact to allow to use as reference to a condition an another rule as building blocks for a chain of complex technics approach or specific artifacts.

##### The rule must be previously defined and called by their name of rule like this :
```
rule myrefrule
{
    strings:
        $s = "artifact"
    condition:
        $s
}
rule hunt_rule
{
    strings:
        $x = "password"
    condition:
        $x and myrefrule
}
```

### Tricks
#### Dotnet malware
##### C# malware can be easily translated into source code by tools like DNSpy, ILSpy, this possible to point to its location of the file using the shortcut ```crtl+x``` or by GUI.

<img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/101/pics/Yara/dot1.png">

##### Once the pointer go to location the code in the file, you can copy/paste the hex sequences with the same structure of code of the different payload for make a hex sequence with jump or wildcard of the different value of opcodes due to different compiler used for built the payloads (different compiler have their own optimisation operations when there translate the source code to asm code).

<img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/101/pics/Yara/dot2.png">

#### Hunting ATM malwares

##### ATMs need XFS middleware that provides client-server architecture for financial applications on Microsoft Windows platform and allow to communicate with service providers via the XFS Manager using a set of API.

##### These largely check for the presence of ```MSXFS.dll``` and instructions to devices via ```WFSExecute``` or lock/open with ```WFSLock/WFSOpen```.

##### Thus, searching via these strings (in ascii, base64...) can be a good start for the search for new ATM malware, it should not however be forgotten that these strings can also be legitimate and be the MSXFS dll used in the ATM (it has already been noted to me that these legitimate dlls had been submitted to Virustotal/Hybrid Analysis).

<h5>It's also possible to emulate this proprietary dll with the following project : <a href="https://github.com/vallejocc/PoC-Fake-Msxfs">here</a></h5>

<h5>For more information about the structure of ATMs, Trend Micro has published an excellent article on this subject <a href="https://documents.trendmicro.com/assets/white_papers/wp-cashing-in-on-atm-malware.pdf">here</a></h5>

#### Translate asm code

<h5> Sometimes, it isn't possible to have the samples because they aren't shared by TLPs or we are looking to find equivalent samples on a different architecture from our samples. This possible to use a <a href="https://shell-storm.org/online/Online-Assembler-and-Disassembler/">online translator</a> for translate the instructions as asm code of the chosen architecture.</h5>

##### Here, on the folowing example, we can translate to the hex code the instruction shared o nthe proofpoint article :

<p align="center">
<img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/101/pics/Yara/asm.png">
</p>
  
##### Note: Some SOC based architecture like MIPS, ARM use a stack of strings for optimize the quality of the programms, in this case, the structure of the code can be the same but the hex code will be greatly different between each compiler and therefore difficult to make a rule with hex sequences

### What approach for creating my rule ?

##### The first question to ask when you want to create a yara rule is what is the purpose of what you want to detect, several possibilities are available by:

<h5>
<ul>
<li>Hunting : The purpose of this type of rule is to detect specific methods such as MITER ATTACK-related, specific functions or artifacts to proactively/actively detect incidents or malware evolutions or the appearance of new malware. </li>
<li>Attribution : The goal is to define a rule for detecting a specific malware or threat actor.</li>
<li>Chain of rules : This rule must be include like a module for detecting a particular case on a common basis. For example, let's imagine in a case of leaks from builders like for conti and babuk, we had artifacts linked to an actor (TA) which exploits these leaks and already made a valid rule to detect this ransomware, it is then interesting to add a reference in the conditions (cf Referencing other rules) so that a chain of rules must be valid (ransomware which leaked and the artifacts of the TA) rather than making a rule again for this slightly modified malware. </li>
</ul>
</h5>

<h5>Once, the type on what kind of rule has been defined, we have different approaches available :</h5>

<h5>
<ul>
<li>Strings : the most basic approach, based to string although this method allows to detect possible samples on various architectures that a hexadecimal sequence approach doesn't allow (because specific to theirs specific architectures), any good threat actor will delete the debug comments or specific artifacts reported by articles of threat intelligence for improve their stealth.</li>
<li>Regex : Regular expression give more mobility on your yara rule although still as affected like a string approach, this approach is particularly effective against strings where the content of can easily be altered by the attacker. </li>
<li>Hex sequences: As previously explained similarity in code structures having common opcodes can be a great tool in the context of a specific assignment of a Yara rule to a particular malware. However, in addition to being case sensitive with different architectures, it needs many different samples to refine with different compilers (even with different versions of the compiler) for be precise, that a cost or for example, not possible due to you have catch an only one (first sample detection). </li>
</ul>
</h5>

##### The final rule can of course include several different approaches depending on the needs, however we must not forget that it is the intelligence that is put in the rule (what does it detect?, what information should we draw? , what strategic advantage does it bring?) that will make the difference depending on the context (for an incident response context, pro-active research, monitoring of the evolution of TA capabilities, etc.)

### Tools 

##### The following section presents tools that I commonly use in implementation or research and being free to the infosec community.

#### Yargen

<h5> A tool (create by <a href="https://twitter.com/cyb3rops">Florian Roth</a>) to generate Yara rules from sample strings submitted as script arguments. Although often deprecated because it is based only on strings and therefore quickly generates obcel rules, this can bring added value in cases where Yara rules have to be made for the search for new samples for an approach via reuse code or find residual artifacts or configuration at the same TA in a mass of samples.

<h5> Repository : <a href="https://github.com/Neo23x0/yarGen">here</a></h5>

#### Binlex

<h5>This tool created by <a href="https://twitter.com/c3rb3ru5d3d53c">3rb3ru5d3d53c</a> allows to extract hex sequences (reuse code) in common with several samples put in argument of the script.</h5>

##### In this following example, we run binlex and select the traits between 8 and 16 bytes (sort the unique traits) : 

```basb
binlex -m auto -i {path} | jq -r 'select((.size > 8 and .size < 16) and (.bytes_sha256 != .traits.sha256)) | .trait' | head -10
33 c0 39 81 39 50 75 12
45 00 00 ?? ?? 00 74 1f
...
```

##### This also possible to generate a Yara rule with the traits found with binlex, its therefore necessary to pass the output in a pipe to ```blyara``` for obtain our Yara rule :

```bash
binlex -m raw:x86 -i {path} | jq -r 'select(.size > 16 and .size < 32) | .trait' | blyara --name myrule -m author {author} -m tlp clear -c 3
rule myrule {
    metadata:
        author = "{author}"
        tlp = "clear"
    strings:
        trait_0 = {8b 01 d6 31 ff 31 8b 42 ?? 01 d0 8b 40 ?? 85 c0 74 4c}
        trait_1 = {49 8b 34  c0 c1 cf ?? 52 57 8b 52 ?? ac 01 c7 38 e0 75 f4}
        trait_2 = {00 00 6a 00 e8 67 00  6a ?? 56 57 68 ?? ?? f8 00 7e 36 ?? ?? ff d5 83 }
    condition:
        3 of them
}
```

##### The output content of binlex being in JSON, it can easily be integrated into trait databases, shared with collaborators...

```bash
binlex -m auto -i {path} -c malware -g {tag} | head -1 | jq
{
  "average_instructions_per_block": 29,
  "blocks": 1,
  "bytes": "ca 1c 89 45 fc 33 d2 8b 45 fc 59 f7 f1 89 45 fc 81 75 fc 3c 95 0e 00 c7 45 f4 0b ff 81 75 f8 30 f4 44 00 c7 45 fc 22 51 53 00 8b 45 fc 6a 3f 59 f7 f1 6a",
  "bytes_entropy": 5.778987,
  "bytes_sha256": "176cdc211b579ea4395b5b0f24f31a54caa02dcf55fd799b34c0eacff4e7ee99",
  "corpus": "malware",
  "cyclomatic_complexity": 3,
  "edges": 2,
  "file_sha256": "7b01c7c835552b17f17ad85b8f900c006def811d708890b5f49f231448aaccd3",
  "file_tlsh": "42E34A10F3D341F7DC9608F219B6B22F9F791E023124DFA987981F57ADB5246A2B981C",
  "instructions": 29,
  "invalid_instructions": 0,
  "mode": "pe:x64",
  "offset": 49711,
  "size": 118,
  "tags": [
    "{tag}"
  ],
  "trait": "1c 83 65 55 8b ec 83 ec ?? ?? cf 4a 88 89 ?? ?? ?? 81 ff 4d ?? 75 21",
  "trait_entropy": 3.45690,
  "trait_sha256": "e13464de470490ab00ab77bc8969b0a2a52be369b61f4dcd16758608cc49e48e",
  "type": "block"
}
```
<h5>Repository : <a href="https://github.com/c3rb3ru5d3d53c/binlex">here</a></h5>

<h5>An introduction To Binlex presented by c3rb3ru5d3d53c
is avialable <a href="https://www.youtube.com/watch?v=hgz5gZB3DxE
">here</a>

#### Yobi

<h5>Created by <a href="https://twitter.com/imp0rtp3/">imp0rtp3</a>, this allow to add as module of firefox an yara scanner on the web page loaded in the browser with the rules imported on the preferences.</h5>

##### Although it doesn't prevent the execution of the code, this one is useful with a bot for proactive research of skimmer, javascript loader which scans lists of domains suspected of being used by threat actors.

<h5>Repository : <a href="https://github.com/imp0rtp3/Yobi">here</a></h5>

#### Cyberchef

##### Needless to present and famous Swiss army knife that is Cyberchef, created by Cyber Swiss Army Knife, a module is available to test Yara rules.
  
<p align="center">
<img src="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/101/pics/Yara/cyber.png">
</p>
  
##### Note: Rather than creating a Yara rule for an archive such as an office document or a zip, it's possible to use cyberchef's Unzip module to decompress the content and test your rule (unzip content can be compressed and so don't match with your traits in the Yara rule.

#### Yara scanner

##### Same functionality as the previous tool but allows you to scan with yara rules on a mass of files or processes in memory.

##### In this case, we can use the ```-r``` argument for recursive between the folders the scan :

<h5>

```
.\yara64.exe {Path_Rule} -r {Path_Samples}
RAN_Royal_Rumble_Dec_2022_1 {Path_Samples}\250bcbfa58da3e713b4ca12edef4dc06358e8986cad15928aa30c44fe4596488.bin
RAN_Royal_Rumble_Dec_2022_1 {Path_Samples}\7cbfea0bff4b373a175327d6cc395f6c176dab1cedf9075e7130508bec4d5393.bin
RAN_Royal_Rumble_Dec_2022_1 {Path_Samples}\de025f921dd477c127fba971b9f90accfb58b117274ba1afb1aaf2222823b6ac.bin
```
</h5>

##### Its also possible to display the strings that match the rule with the ```-s``` argument, however the condition must be valid to be taken into account. Therefore, in the perspective of a debug, put the condition to "1 of them" for see that identifiers don't works of the rule.

<h5>

```
.\yara64.exe {Path_Rule} -r {Path_Samples} -s 
RAN_Royal_Rumble_Dec_2022_1 {Path_Samples}\7cbfea0bff4b373a175327d6cc395f6c176dab1cedf9075e7130508bec4d5393.bin
0x4b12d:$s1: 83 C4 04 8D 85 D4 EF FF FF 83 BD E8 EF FF FF 08 0F 43 85 D4 EF FF FF 6A 00 6A 00 6A 02 6A 00 6A ...
0x4c763:$s2: 68 00 02 00 00 8D 84 24 DC 47 00 00 6A 00 50 E8 A9 3B 12 00 83 C4 0C 8D 84 24 D8 47 00 00 68 E8 ...
0x4df96:$s3: 68 B0 F4 60 00 FF 15 54 51 59 00 50 68 B0 F4 60 00 57 E8 B3 12 00 00 6A 00 6A 00 6A 00 57 E8 27 ...
0xbb7e1:$s4: 50 68 A2 57 59 00 57 68 28 14 5C 00 56 B3 01 E8 8B 1E FB FF FF 74 24 2C C7 44 24 2C 00 00 00 00 ...
RAN_Royal_Rumble_Dec_2022_1 {Path_Samples}\de025f921dd477c127fba971b9f90accfb58b117274ba1afb1aaf2222823b6ac.bin
0x4af8e:$s1: 83 C4 04 8D 85 DC EF FF FF 83 BD F0 EF FF FF 08 0F 43 85 DC EF FF FF 6A 00 6A 00 6A 02 6A 00 6A ...
0x4c153:$s2: 68 00 02 00 00 8D 84 24 DC 47 00 00 6A 00 50 E8 E9 4D 12 00 83 C4 0C 8D 84 24 D8 47 00 00 68 70 ...
0x4ddb2:$s3: 68 20 98 60 00 FF 15 54 01 59 00 50 68 20 98 60 00 57 E8 E7 11 00 00 83 C4 0C 6A 00 6A 00 6A 00 ...
...
```
</h5>
<h5>Repository : <a href="https://github.com/VirusTotal/yara">here</a></h5>

<h5> Note: its possible to do the same thing that cyberchef in extracting the archives in using the yextend module (<a href="https://github.com/BayshoreNetworks/yextend">here</a>).

#### MalwareBazaar

<h5><a href="https://bazaar.abuse.ch/browse/">MalwareBazaar</a> is a project operated by <a href="https://twitter.com/abuse_ch">abuse.ch</a>, allow to shared samples and submit Yara rule on your account and be notified when a sample match your yara rules.</h5>

<h5>It isn't possible to do retrohunting this way however some additional projects like <a href="https://riskmitigation.ch/yara-scan">YARA Scan Service</a> from riskmitigation.ch allows to do a retrohunt the samples submitted on the MalwareBazaar platform.</h5>
