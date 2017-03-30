```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - ArbitraryOverwrite Exploit using GDI -> Low Integrity to System

Arbitrary Overwrite exploit; which exploits a vulnerable function within the HEVD Kernel driver and let us overwrite arbitrary data within Kernelland.

* Basicly the same exploit as https://github.com/Cn33liz/HSEVD-ArbitraryOverwriteGDI except that this code doesn't require NtQuerySystemInformation to leak needed kernel information to Bypass KASLR.
* In this exploit i'm using GDI/Bitmaps to leak the _THREADINFO structure from the current process, using the pti member in the _PUSER_HANDLE_ENTRY structure.
* The pti member points to the _THREADINFO structure which gives us access to the _EPROCESS structure from the current exploit process.
* Using this technique we can avoid using API calls which would normally be blocked from Low Integrity / Browser Sandboxes.

  
Runs on:

```
This exploits has been tested on Windows 8.1 x64 and Windows 10 build 1607
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
To run on x64, you need to install the Windows Driver Kit (WDK), Windows SDK and recompile with Visual Studio.
```

