# Script to parse the overlays

## Requirements

The script requires `lief` in version 0.9 to be installed and thus is currently tied to Python 2.7. You can easily install this dependency by executing

```
pip2 install -r requirements.txt
```

on the command line.

## Usage

To extract the configuration of multiple Winnti samples, simply pass the directory to the script. The script will also recurse into subdirectory and blindly try to parse each file it encounters.

The script does not try to identify Winnti samples and might produce incoherent output if the sample looks too different. Currently, it tries to parse configuration information stored in the executable's _overlay_ as well as _inline_ configurations indicated by a special marker. Further, it also tries to repair broken or "encrypted" files before processing them.

It is recommended to name the samples according to their, e.g., SHA-256 hash for better identification.

To scan a directory called `samples`, simply invoke the script as follows:
```
$ python2 parse.py ./samples

----------------------------------------------------------------------------------------------------

./9c3415507b38694d65262e28f73c3fade5038e455b83d41060f024403c26c9ee: Parsed configuration (overlay).

- Size:    0x50E
- Type:    exe 
- Configuration:

	+0x000:  ""
	+0x304:  "1"
	+0x324:  "shinetsu"
	+0x356:  4B A0 D6 05 
	+0x3C2:  "HpInsightEx.dll"
	+0x3E2:  "kb25489.dat"
	+0x402:  "HPSupportService"
	+0x442:  "HP Insight Extension Support"
	+0x50A:  A9 A1 A5 A6 

----------------------------------------------------------------------------------------------------

./585fa6bbc8bc9dbd8821a0855432c911cf828e834ec86e27546b46652afbfa5e: Parsed configuration (overlay).

- Size:    0x048
- Type:    dll exe 
- Exports: #3
           GetFilterVersion
           HttpFilterProc
           TerminateFilter

- Configuration:

	+0x000:  "DEHENSV533-IIS"
	+0x020:  "de.henkelgroup.net"
	+0x044:  99 DE DF E0 

```

## License

```
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>
```
