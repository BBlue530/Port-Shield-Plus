from collections import defaultdict
from collections import deque

PORTS_ACCESSED = 5

BLOCK_DURATION = 30 # can make perma but need it short for testing

QUARANTINE = "/Quarantine"

BACKUP_FILES ="/Backup"

BACKUP_KEY = "backup_key.key"

program_permissions = 0o644
directory_permissions = 0o000

ip_ports_accessed = defaultdict(set)

log_file = "Port_Shield.txt"

old_seen_programs = set()

owner_email = "bb3250577@gmail.com"

disassemblable_extensions = [
    ".exe", ".dll", ".sys", ".com", ".bin", ".elf", ".out", 
    ".apk", ".app", ".msi", ".pif", ".scr", ".jar", ".macho", 
    ".img", ".rpm", ".deb"
]
non_disassemblable_extensions = [
    ".bat", ".sh", ".py", ".pl", ".js", ".php", ".vbs"
]

BAD_CODE_PATTERN_BAT = [
    "curl", 
    "bitsadmin", 
    "wget", 
    "del", 
    "erase", 
    "rd", 
    "reg add", 
    "netstat", 
    "nc", 
    "runas", 
    "start", 
    "powershell", 
    "schtasks", 
    "echo",
    "base64",
    "Invoke-WebRequest",
    "Set-MpPreference",
    "cmd.exe /c"
]

BAD_CODE_PATTERN_SH = [
    "curl", 
    "wget", 
    "rm -rf", 
    "echo", 
    "nc", 
    "bash", 
    "sudo", 
    "su", 
    "/tmp", 
    "ufw", 
    "iptables", 
    "base64", 
    "uname", 
    "ifconfig", 
    "ps aux", 
    "Invoke-WebRequest", 
    "pwsh"
]

BAD_CODE_PATTERN_PY = [
    "import os", 
    "import subprocess", 
    "os.system", 
    "subprocess.call", 
    "os.remove", 
    "os.rmdir", 
    "shutil.rmtree", 
    "exec", 
    "eval", 
    "open('/dev/sda', 'w')", 
    "socket.socket", 
    "subprocess.Popen", 
    "os.popen", 
    "import shutil", 
    "import socket", 
    "import requests", 
    "import base64", 
    "import time", 
    "import hashlib", 
    "import random"
]

BAD_CODE_PATTERN_PL = [
    "system", 
    "exec", 
    "fork", 
    "eval", 
    "open(FILE, '|-',", 
    "open(FILE, '>',", 
    "unlink", 
    "rmdir", 
    "chmod", 
    "chown", 
    "kill", 
    "socket", 
    "IO::Socket", 
    "LWP::UserAgent", 
    "HTTP::Request", 
    "LWP::Simple", 
    "Net::Telnet", 
    "use Net::SSH", 
    "use IO::Socket::INET", 
    "use HTTP::Request::Common", 
    "use Socket", 
    "system('rm -rf')"
]

BAD_CODE_PATTERN_JS = [
    "eval", 
    "Function(", 
    "setTimeout", 
    "setInterval", 
    "document.write", 
    "document.location", 
    "window.location", 
    "location.href", 
    "XMLHttpRequest", 
    "ActiveXObject", 
    "FileReader", 
    "alert", 
    "unescape", 
    "escape", 
    "eval(function", 
    "atob", 
    "btoa", 
    "location.replace", 
    "document.cookie", 
    "fetch(", 
    "window.open", 
    "window.location.replace", 
    "window.location.href", 
    "document.location.replace", 
    "setInterval(function"
]

BAD_CODE_PATTERN_PHP = [
    "eval(", 
    "base64_decode(", 
    "gzinflate(", 
    "shell_exec(", 
    "system(", 
    "exec(", 
    "passthru(", 
    "popen(", 
    "proc_open(", 
    "curl_exec(", 
    "file_get_contents(", 
    "fopen(", 
    "unlink(", 
    "rmdir(", 
    "chmod(", 
    "chown(", 
    "chgrp(", 
    "getenv(", 
    "putenv(", 
    "$_SERVER", 
    "$_GET", 
    "$_POST", 
    "$_COOKIE", 
    "$_REQUEST", 
    "$_FILES", 
    "$_ENV", 
    "$_SESSION", 
    "header('Location:", 
    "header('X-Forwarded-For:", 
    "header('X-Real-IP:", 
    "http_response_code(", 
    "ob_start(", 
    "ob_get_contents(", 
    "ob_clean("
]

BAD_CODE_PATTERN_VBS = [
    "CreateObject", 
    "WScript.Shell", 
    "WScript.CreateObject", 
    "WScript.Exec", 
    "WScript.Sleep", 
    "Shell.Application", 
    "GetObject", 
    "Run", 
    "Exec", 
    "CreateObject(\"MSXML2.XMLHTTP\")", 
    "CreateObject(\"MSXML2.ServerXMLHTTP\")", 
    "CreateObject(\"Scripting.FileSystemObject\")", 
    "CreateObject(\"WScript.Shell\")", 
    "CreateObject(\"WScript.Network\")", 
    "CreateObject(\"Microsoft.XMLHTTP\")", 
    "CreateObject(\"Microsoft.XMLDOM\")", 
    "ShellExecute", 
    "objShell.Run", 
    "objFSO", 
    "WScript.Quit", 
    "document.write", 
    "MSHTML", 
    "InternetExplorer.Application", 
    "WScript.ScriptFullName", 
    "WScript.Arguments", 
    "WScript.Echo", 
    "WScript.StdOut", 
    "objShell.Popup", 
    "objShell.SendKeys", 
    "WScript.StdIn", 
    "WScript.CreateObject(\"WScript.Shell\")"
]

BAD_CODE_PATTERN = [
    r"mov eax, 0x[A-Fa-f0-9]+;?\s*int 0x80",
    r"xor .*, .*",
    r"jmp .*",
    r"call \[.*\]",
    r"mov \w+, fs:\[.*\]",
    r"pushad\s*;?\s*popad",
    r"int 3",
    r"rdtsc",
    r"pop eax; ret",
    r"mov eax, \[esi\]; xor eax, \w+; mov \[edi\], eax; inc esi; inc edi; loop",
    r"jmp \[.*\]",
    r"mov eax, 0x3E; int 0x80; mov esi, eax; mov eax, 0x5A; int 0x80",
    r"mov eax, \[eprocess\]; mov ebx, \[eax \+ 0x2c8\]; mov \[ebx\], edi",
    r"mov eax, \[sid_history\]; mov \[eax\], new_sid; mov \[eax \+ 4\], old_sid",
    r"mov eax, 0x6F; int 0x80; mov ebx, \[.*\]; mov ecx, \[.*\]",
    r"mov eax, 0x42; int 0x80; mov ebx, \[.*\]; mov ecx, \[.*\]",
    r"mov eax, 0x3; int 0x80; mov ebx, \[.*\]; xor ecx, ecx",
    r"mov eax, 0x3C; int 0x80; mov ebx, \[.*\]; mov ecx, 0x100",
    r"mov eax, 0x3E; int 0x80; mov esi, eax; mov eax, 0x5A; int 0x80",
    r"nop",
    r"push eax; pop eax",
    r"mov eax, eax",
    r"sub eax, eax",
    r"push 0; pop eax",
    r"jmp short .*; .*: .*",
    r"call .*; .*: .*",
    r"mov eax, ebx",
    r"mov ebx, eax",
    r"mov eax, 1",
    r"mov ebx, 1",
    r"xor eax, eax; mov al, 0x66; int 0x80",
    r"jmp short call_shellcode; .*: .*; call .*",
    r"mov eax, \[fs:0x30\]",
    r"mov eax, \[fs:0x18\]",
    r"sidt \[.*\]",
    r"sgdt \[.*\]",
    r"sldt \[.*\]",
    r"in eax, dx",
    r"cpuid",
    r"mov eax, cr3",
    r"mov cr3, eax",
    r"wrmsr",
    r"rdmsr",
    r"sysenter",
    r"sysexit",
    r"iret",
    r"sti",
    r"cli",
    r"pushf",
    r"popf",
    r"lahf",
    r"sahf",
    r"push ss",
    r"pop ss",
    r"push cs",
    r"pop cs",
    r"push ds",
    r"pop ds",
    r"push es",
    r"pop es",
    r"push fs",
    r"pop fs",
    r"push gs",
    r"pop gs",
    r"mov edx, 0xC0000082; rdmsr; mov ecx, eax",
    r"mov eax, 0x2; int 0x80",
    r"mov eax, 0x25; int 0x80",
    r"mov eax, 0xA2; int 0x80",
    r"mov eax, 0x72; int 0x80",
    r"xor ebx, ebx; mov ecx, esp; mov edx, 0x7FFFFFFF; int 0x80",
    r"mov eax, 0xA1; int 0x80",
    r"mov eax, 0x67; int 0x80",
    r"mov eax, 0x47; int 0x80",
    r"int 0x2E",
    r"int 0x21",
    r"push ebp; mov ebp, esp; sub esp, 0x.*; mov eax, \[ebp\+.*\]; call eax",
    r"mov eax, 0x77; int 0x80",
    r"lea eax, \[ebp\+.*\]; call eax",
    r"jmp dword ptr \[.*\]",
    r"call dword ptr \[.*\]",
    r"mov dword ptr \[esp\], eax; call \[.*\]",
    r"lea ecx, \[ebp\+.*\]; call ecx",
    r"mov eax, \[esp\]; add esp, 4; jmp eax",
    r"push dword ptr \[esp\]; ret",
    r"mov eax, \[esp\+.*\]; jmp eax",
    r"add esp, 4; ret",
    r"jmp far ptr \[.*\]",
    r"call far ptr \[.*\]"
]
