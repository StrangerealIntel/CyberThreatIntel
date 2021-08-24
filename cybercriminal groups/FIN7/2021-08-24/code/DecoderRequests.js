var_request  = "Push your data";
var encryption_key = "";
var_type = "decrypt"
if(var_type === "decrypt") {
	var_request = unescape(var_request);
	var request_split = var_request.split("&_&");
	var_request = request_split[0];
	if (request_split.length == 2) { encryption_key = request_split[1].split(""); }
	else { return var_request; }
}
else {
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

console.log(result_string);
