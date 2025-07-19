# Frida Spawn Gater for Windows 11

## Usage
```
usage: frida_spawn_gater [-h] [--timeout SECS] [-q] [-v] PATTERN [FRIDA_ARGS]

Await a Windows process whose name or command line matches PATTERN, then attach Frida.

positional arguments:
  pattern         regex or literal to match the process
  frida_opts      arguments passed verbatim to the frida CLI

options:
  -h, --help      show this help message and exit
  --timeout SECS  abort if no match within SECS (exit 124)
  -q, --quiet     only warnings and errors
  -v, --verbose   debug output
```

## Example

Wait at most 30 seconds for `notepad.exe` to spawn, attaching with frida and forwarding the `-l agent.js` args to frida.
```bash
python frida_spawn_gater.py --timeout 30 notepad.exe -l agent.js
```
