# Volatility Sample - Valle Grande

## Resources

The following resources are required to continue:

1. Volatility 2.6
2. python >= 2.7
3. [Memory dump](https://drive.google.com/file/d/1fJ35gJRoqGVeI0x5K_ljHRYWcCCngl-z/view?usp=sharing)

## Process

1. imageinfo

     Command:
     ~~~Bash
     python2 vol.py imageinfo -f ../cridex.vmem
     ~~~

     Expected output:
     ~~~
     INFO :    volatility.debug      : Determining profile based on KDBG search...
               Suggested Profile(s)  : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                          AS Layer1  : IA32PagedMemoryPae (Kernel AS)
                          AS Layer2  : FileAddressSpace (/home/jhordycg/Downloads/cridex.vmem)
                           PAE type  : PAE
                                DTB  : 0x2fe000L
                               KDBG  : 0x80545ae0L
               Number of Processors  : 1
          Image Type (Service Pack)  : 3
                     KPCR for CPU 0  : 0xffdff000L
                  KUSER_SHARED_DATA  : 0xffdf0000L
                Image date and time  : 2012-07-22 02:45:08 UTC+0000
          Image local date and time  : 2012-07-21 22:45:08 -0400
     ~~~

2. pslist

     Command: 
     ~~~bash
     python2 vol.py --profile=WinXPSP2x86 -f ../cridex.vmem pslist 
     ~~~

     Expected output:
     ~~~
     Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
     ---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
     0x823c89c8 System                    4      0     53      240 ------      0                                                              
     0x822f1020 smss.exe                368      4      3       19 ------      0 2012-07-22 02:42:31 UTC+0000                                 
     0x822a0598 csrss.exe               584    368      9      326      0      0 2012-07-22 02:42:32 UTC+0000                                 
     0x82298700 winlogon.exe            608    368     23      519      0      0 2012-07-22 02:42:32 UTC+0000                                 
     0x81e2ab28 services.exe            652    608     16      243      0      0 2012-07-22 02:42:32 UTC+0000                                 
     0x81e2a3b8 lsass.exe               664    608     24      330      0      0 2012-07-22 02:42:32 UTC+0000                                 
     0x82311360 svchost.exe             824    652     20      194      0      0 2012-07-22 02:42:33 UTC+0000                                 
     0x81e29ab8 svchost.exe             908    652      9      226      0      0 2012-07-22 02:42:33 UTC+0000                                 
     0x823001d0 svchost.exe            1004    652     64     1118      0      0 2012-07-22 02:42:33 UTC+0000                                 
     0x821dfda0 svchost.exe            1056    652      5       60      0      0 2012-07-22 02:42:33 UTC+0000                                 
     0x82295650 svchost.exe            1220    652     15      197      0      0 2012-07-22 02:42:35 UTC+0000                                 
     0x821dea70 explorer.exe           1484   1464     17      415      0      0 2012-07-22 02:42:36 UTC+0000                                 
     0x81eb17b8 spoolsv.exe            1512    652     14      113      0      0 2012-07-22 02:42:36 UTC+0000                                 
     0x81e7bda0 reader_sl.exe          1640   1484      5       39      0      0 2012-07-22 02:42:36 UTC+0000                                 
     0x820e8da0 alg.exe                 788    652      7      104      0      0 2012-07-22 02:43:01 UTC+0000                                 
     0x821fcda0 wuauclt.exe            1136   1004      8      173      0      0 2012-07-22 02:43:46 UTC+0000                                 
     0x8205bda0 wuauclt.exe            1588   1004      5      132      0      0 2012-07-22 02:44:01 UTC+0000
     ~~~

3. pstree

     Command:
     ~~~bash
     python2 vol.py --profile=WinXPSP2x86 -f ../cridex.vmem pstree
     ~~~

     Expected output:
     ~~~
     Name                                                  Pid   PPid   Thds   Hnds Time
     -------------------------------------------------- ------ ------ ------ ------ ----
     0x823c89c8:System                                       4      0     53    240 1970-01-01 00:00:00 UTC+0000
     . 0x822f1020:smss.exe                                 368      4      3     19 2012-07-22 02:42:31 UTC+0000
     .. 0x82298700:winlogon.exe                            608    368     23    519 2012-07-22 02:42:32 UTC+0000
     ... 0x81e2ab28:services.exe                           652    608     16    243 2012-07-22 02:42:32 UTC+0000
     .... 0x821dfda0:svchost.exe                          1056    652      5     60 2012-07-22 02:42:33 UTC+0000
     .... 0x81eb17b8:spoolsv.exe                          1512    652     14    113 2012-07-22 02:42:36 UTC+0000
     .... 0x81e29ab8:svchost.exe                           908    652      9    226 2012-07-22 02:42:33 UTC+0000
     .... 0x823001d0:svchost.exe                          1004    652     64   1118 2012-07-22 02:42:33 UTC+0000
     ..... 0x8205bda0:wuauclt.exe                         1588   1004      5    132 2012-07-22 02:44:01 UTC+0000
     ..... 0x821fcda0:wuauclt.exe                         1136   1004      8    173 2012-07-22 02:43:46 UTC+0000
     .... 0x82311360:svchost.exe                           824    652     20    194 2012-07-22 02:42:33 UTC+0000
     .... 0x820e8da0:alg.exe                               788    652      7    104 2012-07-22 02:43:01 UTC+0000
     .... 0x82295650:svchost.exe                          1220    652     15    197 2012-07-22 02:42:35 UTC+0000
     ... 0x81e2a3b8:lsass.exe                              664    608     24    330 2012-07-22 02:42:32 UTC+0000
     .. 0x822a0598:csrss.exe                               584    368      9    326 2012-07-22 02:42:32 UTC+0000
     0x821dea70:explorer.exe                              1484   1464     17    415 2012-07-22 02:42:36 UTC+0000
     . 0x81e7bda0:reader_sl.exe                           1640   1484      5     39 2012-07-22 02:42:36 UTC+0000
     ~~~

4. cmdline

     Command:
     ~~~bash
     python2 vol.py --profile=WinXPSP2x86 -f ../cridex.vmem cmdline
     ~~~

     Expected output:
     ~~~
     ...
     
     reader_sl.exe pid:   1640
     Command line : "C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe" 
     ************************************************************************
     
     ...

     wuauclt.exe pid:   1588
     Command line : "C:\WINDOWS\system32\wuauclt.exe"

     ...
     ~~~

5. connections

     Command:
     ~~~bash
     python2 vol.py --profile=WinXPSP2x86 -f ../cridex.vmem connections
     ~~~

     Expected output:
     ~~~
     Offset(V)  Local Address             Remote Address            Pid
     ---------- ------------------------- ------------------------- ---
     0x81e87620 172.16.112.128:1038       41.168.5.140:8080         1484
     ~~~

6. connscan

     Command:
     ~~~bash
     python2 vol.py -f ../cridex.vmem connscan
     ~~~

     Expected output:
     ~~~bash
     Offset(P)  Local Address             Remote Address            Pid
     ---------- ------------------------- ------------------------- ---
     0x02087620 172.16.112.128:1038       41.168.5.140:8080         1484
     0x023a8008 172.16.112.128:1037       125.19.103.198:8080       1484
     ~~~

     From the above IP addresses, we'll can get more information with the help of some web pages like [WhatIsMyIPAddress](htpp://whatismyipaddress.com):
     
     - [41.168.5.140](https://whatismyipaddress.com/ip/41.168.5.140) 
     - [125.19.103.198](https://whatismyipaddress.com/ip/125.19.103.198) 

7. dlllist

     Command:
     ~~~bash
     python2 vol.py -f ../cridex.vmem dlllist -p 1484
     ~~~

     Expected output:
     ~~~
     explorer.exe pid:   1484
     Command line : C:\WINDOWS\Explorer.EXE
     Service Pack 3

     Base             Size  LoadCount LoadTime                       Path
     ---------- ---------- ---------- ------------------------------ ----
     0x01000000    0xff000     0xffff                                C:\WINDOWS\Explorer.EXE
     0x7c900000    0xaf000     0xffff                                C:\WINDOWS\system32\ntdll.dll
     0x7c800000    0xf6000     0xffff                                C:\WINDOWS\system32\kernel32.dll
     0x77dd0000    0x9b000     0xffff                                C:\WINDOWS\system32\ADVAPI32.dll
     0x77e70000    0x92000     0xffff                                C:\WINDOWS\system32\RPCRT4.dll
     0x77fe0000    0x11000     0xffff                                C:\WINDOWS\system32\Secur32.dll
     0x75f80000    0xfd000     0xffff                                C:\WINDOWS\system32\BROWSEUI.dll
     0x77f10000    0x49000     0xffff                                C:\WINDOWS\system32\GDI32.dll
     0x7e410000    0x91000     0xffff                                C:\WINDOWS\system32\USER32.dll
     0x77c10000    0x58000     0xffff                                C:\WINDOWS\system32\msvcrt.dll
     0x774e0000   0x13d000     0xffff                                C:\WINDOWS\system32\ole32.dll
     0x77f60000    0x76000     0xffff                                C:\WINDOWS\system32\SHLWAPI.dll
     0x77120000    0x8b000     0xffff                                C:\WINDOWS\system32\OLEAUT32.dll
     0x7e290000   0x171000     0xffff                                C:\WINDOWS\system32\SHDOCVW.dll
     0x77a80000    0x95000     0xffff                                C:\WINDOWS\system32\CRYPT32.dll
     0x77b20000    0x12000     0xffff                                C:\WINDOWS\system32\MSASN1.dll
     0x754d0000    0x80000     0xffff                                C:\WINDOWS\system32\CRYPTUI.dll
     0x5b860000    0x55000     0xffff                                C:\WINDOWS\system32\NETAPI32.dll
     0x77c00000     0x8000     0xffff                                C:\WINDOWS\system32\VERSION.dll
     0x771b0000    0xaa000     0xffff                                C:\WINDOWS\system32\WININET.dll
     0x76c30000    0x2e000     0xffff                                C:\WINDOWS\system32\WINTRUST.dll
     ...
     ~~~

8. procdump

     Command:
     ~~~bash
     # Create a new folder to save the following files.
     mkdir dump
     python2 vol.py -f ../cridex.vmem procdump -D dump -p 1484
     ~~~

     Expected output:
     ~~~
     Process(V) ImageBase  Name                 Result
     ---------- ---------- -------------------- ------
     0x821dea70 0x01000000 explorer.exe         OK: executable.1484.exe
     ~~~

     On the [VirusTotal](https://www.virustotal.com/gui/home/upload) page we will analyze if the executable files are malware.
     - [executable.1484.exe](https://www.virustotal.com/gui/file/48db195007e5ae9fc1246506564af154927e9f3fbfca0b4054552804027abbf2)
     - [executable.1640.exe](https://www.virustotal.com/gui/file/5b136147911b041f0126ce82dfd24c4e2c79553b65d3240ecea2dcab4452dcb5)
     - [executable.1588.exe](https://www.virustotal.com/gui/file/5b136147911b041f0126ce82dfd24c4e2c79553b65d3240ecea2dcab4452dcb5)

## Members

- Jhordy Caceres
- Victor Geovani