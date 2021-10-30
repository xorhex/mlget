## mlget

```
          _____                    _____            _____                    _____                _____          
         /\    \                  /\    \          /\    \                  /\    \              /\    \         
        /::\____\                /::\____\        /::\    \                /::\    \            /::\    \        
       /::::|   |               /:::/    /       /::::\    \              /::::\    \           \:::\    \       
      /:::::|   |              /:::/    /       /::::::\    \            /::::::\    \           \:::\    \      
     /::::::|   |             /:::/    /       /:::/\:::\    \          /:::/\:::\    \           \:::\    \     
    /:::/|::|   |            /:::/    /       /:::/  \:::\    \        /:::/__\:::\    \           \:::\    \    
   /:::/ |::|   |           /:::/    /       /:::/    \:::\    \      /::::\   \:::\    \          /::::\    \   
  /:::/  |::|___|______    /:::/    /       /:::/    / \:::\    \    /::::::\   \:::\    \        /::::::\    \  
 /:::/   |::::::::\    \  /:::/    /       /:::/    /   \:::\ ___\  /:::/\:::\   \:::\    \      /:::/\:::\    \ 
/:::/    |:::::::::\____\/:::/____/       /:::/____/  ___\:::|    |/:::/__\:::\   \:::\____\    /:::/  \:::\____\
\::/    / ~~~~~/:::/    /\:::\    \       \:::\    \ /\  /:::|____|\:::\   \:::\   \::/    /   /:::/    \::/    /
 \/____/      /:::/    /  \:::\    \       \:::\    /::\ \::/    /  \:::\   \:::\   \/____/   /:::/    / \/____/ 
             /:::/    /    \:::\    \       \:::\   \:::\ \/____/    \:::\   \:::\    \      /:::/    /          
            /:::/    /      \:::\    \       \:::\   \:::\____\       \:::\   \:::\____\    /:::/    /           
           /:::/    /        \:::\    \       \:::\  /:::/    /        \:::\   \::/    /    \::/    /            
          /:::/    /          \:::\    \       \:::\/:::/    /          \:::\   \/____/      \/____/             
         /:::/    /            \:::\    \       \::::::/    /            \:::\    \                              
        /:::/    /              \:::\____\       \::::/    /              \:::\____\                             
        \::/    /                \::/    /        \::/____/                \::/    /                             
         \/____/                  \/____/                                   \/____/                              
```                                                                                                              

![Build](https://github.com/xorhex/mlget/actions/workflows/go.yml/badge.svg)

### What is it

Use mlget to query multiple sources for a given malware hash and download it.  The thought is to save time querying each source individually.

Currently queries:

  - cp (Cape Sandbox)
  - ha (Hybrid Analysis)
  - iq (Inquest Labs)
  - js (Joe Sandbox)
  - mp (Malpedia)
  - ms (Malshare)
  - mb (Malware Bazaar)
  - mw (Malware Database)
  - os (Objective-See)
  - ps (PolySwarm)
  - tg (Triage)
  - um (UnpacMe)
  - vt (VirusTotal)

Only Malware Bazaar and Objective-See does not require a key, the rest require a key.  The config file needs to be placed in the user's home directory (essentially where `os.UserHomeDir()` resolves to).

### Overview + Build + Usage Instructions

[Mlget Blog Post](https://blog.xorhex.com/blog/mlget-for-all-your-malware-download-needs/)

### License

MIT License

Copyright (c) 2021 @xorhex

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
