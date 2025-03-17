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
