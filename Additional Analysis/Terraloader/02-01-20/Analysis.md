# Analysis of Terraloader sample
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Cyber kill chain](#Cyber-kill-chain)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [Ressources](#Ressources)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>This analysis presents a javascript loader (Terraloader) using many arrays, calculations and variables in memory for make harder the analysis and lowering the detection rate on antivirus. This loader have two stagers.</h6>
<h6> The first block of the payload is the globals values used for decode the first layer, this give the tab of values as key, the offset, the base of characters and the rest for initialized the variables used for the second stage.</h6>

```javascript
var tab = [];
var base = [];
var offset_tab = 0;
var blawp718 = "";
var blawp4015 = "";
var blawp73 = "";
var blawp1023 = "";
var blawp7173 = "";
var blawp7178 = "";
var blawp9073 = "";
var blawp77 = "";
var blawp5376 = "";
var blawp6122 = "";
var blawp23 = "";
var blawp7 = "";
```

<h6>The next block is composed of two functions, the first use a switch case condition to select the character corresponding to its ASCII value, one interesting thing to note is the fact that the default case isn't set, it is automatically created by an IDE , which is more the sign of a generation by a tool.</h6>

```javascript
function get_ascii_value(arg) 
{
 var x = "";
 switch (arg) {
  case 32:
   x = " ";
   break;
  case 33:
   x = "!";
   break;
  case 34:
   x = '"';
   break;
  case 35:
   x = "#";
   break;
  case 36:
   x = "$";
   break;
  case 37:
   x = "%";
   break;
  case 38:
   x = "&";
   break;
  case 39:
   x = "'";
   break;
  case 40:
   x = "(";
   break;
  case 41:
   x = ")";
   break;
  case 42:
   x = "*";
   break;
  case 43:
   x = "+";
   break;
  case 44:
   x = ",";
   break;
  case 45:
   x = "-";
   break;
  case 46:
   x = ".";
   break;
  case 47:
   x = "/";
   break;
  case 48:
   x = "0";
   break;
  case 49:
   x = "1";
   break;
  case 50:
   x = "2";
   break;
  case 51:
   x = "3";
   break;
  case 52:
   x = "4";
   break;
  case 53:
   x = "5";
   break;
  case 54:
   x = "6";
   break;
  case 55:
   x = "7";
   break;
  case 56:
   x = "8";
   break;
  case 57:
   x = "9";
   break;
  case 58:
   x = ":";
   break;
  case 59:
   x = ";";
   break;
  case 60:
   x = "<";
   break;
  case 61:
   x = "=";
   break;
  case 62:
   x = ">";
   break;
  case 63:
   x = "?";
   break;
  case 64:
   x = "@";
   break;
  case 65:
   x = "A";
   break;
  case 66:
   x = "B";
   break;
  case 67:
   x = "C";
   break;
  case 68:
   x = "D";
   break;
  case 69:
   x = "E";
   break;
  case 70:
   x = "F";
   break;
  case 71:
   x = "G";
   break;
  case 72:
   x = "H";
   break;
  case 73:
   x = "I";
   break;
  case 74:
   x = "J";
   break;
  case 75:
   x = "K";
   break;
  case 76:
   x = "L";
   break;
  case 77:
   x = "M";
   break;
  case 78:
   x = "N";
   break;
  case 79:
   x = "O";
   break;
  case 80:
   x = "P";
   break;
  case 81:
   x = "Q";
   break;
  case 82:
   x = "R";
   break;
  case 83:
   x = "S";
   break;
  case 84:
   x = "T";
   break;
  case 85:
   x = "U";
   break;
  case 86:
   x = "V";
   break;
  case 87:
   x = "W";
   break;
  case 88:
   x = "X";
   break;
  case 89:
   x = "Y";
   break;
  case 90:
   x = "Z";
   break;
  case 91:
   x = "[";
   break;
  case 92:
   x = "\\";
   break;
  case 93:
   x = "]";
   break;
  case 94:
   x = "^";
   break;
  case 95:
   x = "_";
   break;
  case 96:
   x = "`";
   break;
  case 97:
   x = "a";
   break;
  case 98:
   x = "b";
   break;
  case 99:
   x = "c";
   break;
  case 100:
   x = "d";
   break;
  case 101:
   x = "e";
   break;
  case 102:
   x = "f";
   break;
  case 103:
   x = "g";
   break;
  case 104:
   x = "h";
   break;
  case 105:
   x = "i";
   break;
  case 106:
   x = "j";
   break;
  case 107:
   x = "k";
   break;
  case 108:
   x = "l";
   break;
  case 109:
   x = "m";
   break;
  case 110:
   x = "n";
   break;
  case 111:
   x = "o";
   break;
  case 112:
   x = "p";
   break;
  case 113:
   x = "q";
   break;
  case 114:
   x = "r";
   break;
  case 115:
   x = "s";
   break;
  case 116:
   x = "t";
   break;
  case 117:
   x = "u";
   break;
  case 118:
   x = "v";
   break;
  case 119:
   x = "w";
   break;
  case 120:
   x = "x";
   break;
  case 121:
   x = "y";
   break;
  case 122:
   x = "z";
   break;
  case 123:
   x = "{";
   break;
  case 124:
   x = "|";
   break;
  case 125:
   x = "}";
   break;
  case 126:
   x = "~";
   break;
 }
 return x;
}
```
<h6>The second function reconstructs by a series of loops while for build the base of characters used by loader</h6>

```javascript
function get_base() 
{
 var tab_string = [];
 var tab_index = 0;
 var i = 65;
 while (i < 91) 
 {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 i = 97 ;
 while (i < 123) 
 {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 i = 48;
 while (i < 58) 
 {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 tab_string[tab_index] = get_ascii_value(33);
 tab_index = tab_index + 1;
 i = 35;
 while (i < 39) {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 i = 40;
 while (i < 45) {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 tab_string[tab_index] = get_ascii_value((4450 - 4404));
 tab_index = tab_index + 1;
 tab_string[tab_index] = get_ascii_value((2169 - 2122));
 tab_index = tab_index + 1;
 i = 58;
 while (i < 65) {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 tab_string[tab_index] = get_ascii_value(91);
 tab_index = tab_index + 1;
 tab_string[tab_index] = get_ascii_value(93);
 tab_index = tab_index + 1;
 i = 94;
 while (i < 97) {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 i = 123;
 while (i < 127) {
  tab_string[tab_index] = get_ascii_value(i);
  i = i + 1;
  tab_index = tab_index + 1;
 }
 tab_string[tab_index] = get_ascii_value(34);
 return tab_string;
}
function find_index(tab, search_element) 
{
 var index = 0;
 do {
  if (tab[index] === search_element) {return index;}
  index = index + 1;
 } while (index < get_length(tab));
}
```

<h2> Cyber kill chain <a name="Cyber-kill-chain"></a></h2>
<h6>The process graph resume cyber kill chains used by the attacker :</h6>
<p align="center">
  <img src="https://raw.githubusercontent.com/StrangerealIntel/CyberThreatIntel/master/Indian/APT/SideWinder/25-12-19/Pictures/Cyber.png">
</p>
<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> List of all the Indicators Of Compromise (IOC)</h6>

|Indicator|Description|
| ------------- |:-------------:|
|||

<h6> The IOC can be exported in <a href="">JSON</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
||||

<h6> This can be exported as JSON format <a href="">Export in JSON</a></h6>
<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>

* [https://twitter.com/Ledtech3/status/1211760115008888832](https://twitter.com/Ledtech3/status/1211760115008888832) 

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>

* [Job Description.js](https://app.any.run/tasks/1b909852-114b-4a4c-8b90-f36016501d6d)

<h6> Resources : </h6><a name="Ressources"></a>

* [Analysis of TerraLoader sample from Vitali Kremez](https://twitter.com/VK_Intel/status/1211758023376592896)
