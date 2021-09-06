## New York Minute #1 : FINished in 7 minutes

#### The goal of this article is to explain how deal quickly with the FIN7 JS implants step by step.

#### Firstly, the first interesting reflex is to split the malicious code with the end-of-instruction separator ";", this allows you to quickly have a global view of the script rather than a single line. The only flaw is that this separator is also used by for loops, however I have a tip for the next steps. 

#### A skilled eye quickly sees that the first lines are linked for deobfuscation of strings, which is often the case in scripting languages because objects and functions often need to be defined before being called. It is therefore necessary to isolate all these parts to create our decoder (array, code to perform to the array with the function).

<img src=".\Pictures\1.png"></img>

#### As said previously, we can see the default to split with the end separator ";", this cut the for loops. 

<img src=".\Pictures\2.png"></img>

#### This time to show one of your best tools against the obfuscated scripts :  ```de4js``` . This can be installed on your system but some online sites propose this. This tool can remove various obfuscation techniques used by packers, hexadecimal representation to strings, execute commands in eval and reorganize the code properly (see our beautiful "for" loops).

<img src=".\Pictures\3.png"></img>

#### Now we can observe that the function, return the result from another function "self-executed" for making the manipulation of the array. The output is nested with another function, that a current method used for check if the debug rights is present is an indicator that a debug a session with debugger, this part is to remove.

<img src=".\Pictures\4.png"></img>

#### The next step is to search the reference, the second array and the steps performed once decoded, we note the while with the switch condition and an increment that a good indicator (also a signature for detecting FIN7 implants) to order the next instructions to execute with a switch case. RegExp allow to define regular expression for parse and remove junk code by the second argument, ActiveXObject for getting an object ActiveX for COM object and eval for run the command.

<img src=".\Pictures\5.png"></img>

#### This time to get the order and remove the obfuscation of array in using your favorite sandbox for run and get the results with a simple console.log(), we have the order of the commands and the second array decoded.

<img src=".\Pictures\6.png"></img>

#### You haven't any need to get the expression for find/replace and remove the junk code, this easily predictable. Get the result and use de4js make more easy to understand the next part of code that executed.

<img src=".\Pictures\7.png"></img>

#### Now we note that a loop with a for is performed for getting the next layer and execute by an eval in keep the code of the previous part.

<img src=".\Pictures\8.png"></img>

<img src=".\Pictures\9.png"></img>

#### On another console just remove the eval for avoiding to execute the code and you have the second layer.

<img src=".\Pictures\10.png"></img>

#### We can see all the recon operations performed by the script, two important things must be observed. First, the exchange is encoded/decoded with a key that given in split the request with "&_&". The second is the random generator of path for the URI and locates the exchange for the third layer.

<img src=".\Pictures\11.png"></img>

<h4> Now we need to have a capture (pcap) of the exchange with the C2 and remove the TLS layer. For this, we need to fix the SSL keys that be used by the system in the environment variables. You can follow the <a href="https://unit42.paloaltonetworks.com/wireshark-tutorial-decrypting-https-traffic/"> Palo Alto tutorial</a> for setup on your system. Here, you use Anyrun session for getting the Pcap and the SSL keys like this.</h4>

<img src=".\Pictures\12.png"></img>

#### We will use wireshark for this by opening the Pcap and adding the keys in edit> preferences> protocols> TLS

<img src=".\Pictures\13.png"></img>

#### Now we can following the exchange on the TLS stream and get the last layer that encoded with the key.

<img src=".\Pictures\14.png"></img>

#### You have just to edit the function for decode the stream from the code of second layer and you have the last layer.
```js
var_request = "DATA TLS Stream"
var encryption_key = "";
var_type = "decrypt"
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
console.log(result_string)
```

<img src=".\Pictures\15.png"></img>

#### Congratulations, you now know how to remove commonly used dofuscation layers and extract information by breaking TLS with the trick of forcing the use of its own SSL keys. 
