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

### What is it

Use mlget to query multiple sources for a given malware hash and download it.  The thought is to save time querying each source individually.

Currently queries:

- tg (triage)
- mb (malwarebazaar)
- ms (malshare)
- ha (HybirdAnlysis)
- vt (VirusTotal)
- cp (Cape Sandbox)
- mw (Malware Database)
- ps (PolySwarm)
- iq (InquestLabs)

Only Malware Bazaar does not require a key, the rest require a key.  The config file needs to be placed in the user's home directory (essentially where `os.UserHomeDir()` resolves to).

#### Build

Assuming golang is installed and this repo is checked out; simply run:
```
go get -u
go mod tidy
go build
```

from the cloned directory to compile the application and `./mlget` to run it.

#### Setup Config

Run mlget on the commandline without any flags to have it generate the yaml config template.

```
> ./mlget
Config does not exist.  Create config? [Y|n]
```

Hit enter and it will create the config, `.mlget.yml`, in the user's home dir.

```
Created /home/dir/.mlget.yml.  Make sure to fill out the API keys for the services you want to use.
No hashes found
mlget - A command line tool to download malware from a variety of sources

Usage: ./mlget [OPTIONS] argument ...
  -c    Parse and print the config file
  -d string
        The service to download the malware from.
          Must be one of:
          - tg (triage)
          - mb (malwarebazaar)
          - ms (malshare)
          - ha (HybirdAnlysis)
          - vt (VirusTotal)
          - cp (Cape Sandbox)
          - mw (Malware Database)
          - ps (PolySwarm)
          - iq (InquestLabs)
        If omitted, all services will be tried.
  -h    Print the help message
  -ne
        Do not extract malware from archive file.
        Currently this only effects MalwareBazaar and HybridAnalysis
  -o    Write to a file the hashes not found (for later use with the -r flag)
  -r string
        Read in a file of hashes (one per line)
  -ru string
        Read hashes from file to download.  Replace entries in the file with just the hashes that were not found (for next time).
  -u    Upload downloaded files to the MWDB instance specified in the mlget.yml file.
  -ud
        Upload downloaded files to the MWDB instance specified in the mlget.yml file.
        Delete the files after successful upload

Example Usage: mlget <sha256>
Example Usage: mlget -d mb <sha256>
```

Fill out the API keys where needed.  If the service does not have an API key then it will be skipped.

```
malshare:
  api: ""
  host: https://malshare.com
malwarebazar:
  host: https://mb-api.abuse.ch/api/v1
mwdb:
  api: ""
  host: https://mwdb.cert.pl/api
virustotal:
  api: ""
  host: https://www.virustotal.com/api/v3
triage:
  api: ""
  host: https://api.tria.ge/v0
hybridanalysis:
  api: ""
  host: https://www.hybrid-analysis.com/api/v2
polyswarm:
  api: ""
  host: https://api.polyswarm.network/v2
capesandbox:
  api: ""
  host: https://www.capesandbox.com/apiv2
inquestlabs:
  api: ""
  host: https://labs.inquest.net/api
uploadtomwdb:
  api: ""
  host: ""
```

Fill out the last last one `uploadtomwdb` if you want to take advantage of your private [MWDB](https://github.com/CERT-Polska/mwdb-core) instance to upload the files to.  All of the others are for download only.

### Example Usage

#### Download from All sources

```
mlget e6ba5de3a9b0287291def0317789b871fa1984a11021d55d3a0371c6d65a872b 1c7897a902b35570a9620c64a2926cd5d594d4ff5a033e28a400981d14516600
```
Multiple hash can be passed.

#### Download from Specific Source

```
mlget -d tg e6ba5de3a9b0287291def0317789b871fa1984a11021d55d3a0371c6d65a872b 1c7897a902b35570a9620c64a2926cd5d594d4ff5a033e28a400981d14516600
```

#### Hashes from a file

Hashes can be read from both the command line and a file (one hash per line) at the same time

```
mlget -r hashes.txt e6ba5de3a9b0287291def0317789b871fa1984a11021d55d3a0371c6d65a872b 1c7897a902b35570a9620c64a2926cd5d594d4ff5a033e28a400981d14516600
```

#### Recording the hashes not found for next time

This will output the unfound hashes to a new file:
```
mlget -r hashes.txt -o e6ba5de3a9b0287291def0317789b871fa1984a11021d55d3a0371c6d65a872b 1c7897a902b35570a9620c64a2926cd5d594d4ff5a033e28a400981d14516600
```

This will update current file so it only contains the hashes not found
```
mlget -ru download.txt e6ba5de3a9b0287291def0317789b871fa1984a11021d55d3a0371c6d65a872b 1c7897a902b35570a9620c64a2926cd5d594d4ff5a033e28a400981d14516600
```

#### Other Commands

```
mlget -h

mlget - A command line tool to download malware from a variety of sources

Usage: ./mlget [OPTIONS] argument ...
      --c           Parse and print the config file
      --d string    The service to download the malware from.
                      Must be one of:
                      - tg (Triage)
                      - mb (Malware Bazaar)
                      - ms (Malshare)
                      - ha (HybirdAnlysis)
                      - vt (VirusTotal)
                      - cp (Cape Sandbox)
                      - mw (Malware Database)
                      - ps (PolySwarm)
                      - iq (InquestLabs)
                    If omitted, all services will be tried.
      --h           Print the help message
      --ne          Do not extract malware from archive file.
                    Currently this only effects MalwareBazaar and HybridAnalysis
      --o           Write to a file the hashes not found (for later use with the -r flag)
      --r string    Read in a file of hashes (one per line)
      --ru string   Read hashes from file to download.  Replace entries in the file with just the hashes that were not found (for next time).
      --t strings   Tag the sample when uploading to your own instance of MWDB.
      --u           Upload downloaded files to the MWDB instance specified in the mlget.yml file.
      --ud          Upload downloaded files to the MWDB instance specified in the mlget.yml file.
                    Delete the files after successful upload

Example Usage: mlget <sha256>
Example Usage: mlget -d mb <sha256>
```


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
