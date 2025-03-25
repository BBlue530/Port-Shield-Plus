from capstone import *
import pefile
from elftools.elf.elffile import ELFFile
import os
import re
from Variables import BAD_CODE_PATTERN
from ProgramMonitoring.HandleBadProgram import quarantine_program

###############################################################################################################

def read_binary_file(path_to_program):
    with open(path_to_program, "rb") as f:
        binary_data = f.read()
    return binary_data

###############################################################################################################

def disassemble_binary(binary_data, start_address=0x1000, architecture='x86', mode=64):
    if architecture == 'x86':
        if mode == 64:
            md = Cs(CS_ARCH_X86, CS_MODE_64)  # 64 bit x86
        elif mode == 32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)  # 32 bit x86
    elif architecture == 'arm':
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)  # ARM architecture
    elif architecture == 'mips':
        md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)  # MIPS architecture
    else:
        raise ValueError(f"Unsupported architecture: {architecture}")

    # Disassembles the binary and returns the instructions
    instructions = []
    for instruction in md.disasm(binary_data, start_address):
        instructions.append({
            'address': instruction.address,
            'mnemonic': instruction.mnemonic,
            'operand': instruction.op_str
        })
    return instructions

###############################################################################################################

def save_disassembly_to_file(instructions, output_file):
    with open(output_file, 'w') as out:
        for instruction in instructions:
            out.write(f"[i] 0x{instruction['address']:x}:\t{instruction['mnemonic']}\t{instruction['operand']}\n")
    print(f"[i] Disassembly saved: {output_file}")

def print_disassembly(instructions):
    for instruction in instructions:
        print(f"[i] 0x{instruction['address']:x}:\t{instruction['mnemonic']}\t{instruction['operand']}")

###############################################################################################################

def extract_code_section(binary_data, path_to_program):
    try:
        if binary_data[:2] == b'MZ':
            return extract_code_section_from_pe(binary_data)
        
        elif binary_data[:4] == b'\x7fELF':
            return extract_code_section_from_elf(binary_data)
        
        else:
            raise ValueError("[!] Wrong binary format")

    except Exception as e:
        print(f"[!] Error extracting code from: {path_to_program}: {e}")
        return None

def extract_code_section_from_pe(binary_data):
    pe = pefile.PE(data=binary_data)
    
    for section in pe.sections:
        if b'.text' in section.Name:
            return section.get_data()
    
    raise ValueError("[!] .text section not found: PE")

def extract_code_section_from_elf(binary_data):
    elf_file = ELFFile(io.BytesIO(binary_data))
    
    for section in elf_file.iter_sections():
        if section.name == '.text':
            return section.data()
    
    raise ValueError("[!] .text section not found: ELF")

###############################################################################################################

def disassemble_program(path_to_program, output_file="disassembled.txt"):
    print(f"[i] Reading: {path_to_program}")
    binary_data = read_binary_file(path_to_program)

    print("[i] Disassembling...")
    code_section = extract_code_section(binary_data, path_to_program)
    if code_section is None:
        print(f"[!] Unable to extract from: {path_to_program}")
        return
    
    instructions = disassemble_binary(code_section, start_address=0x1000, architecture='x86', mode=64)

    # Prints and saves the disassembly. Will prolly get rid of the print later but keeping it for now
    print_disassembly(instructions)
    save_disassembly_to_file(instructions, output_file)
    check_for_bad_code(path_to_program, output_file)

###############################################################################################################

def check_for_bad_code(path_to_program, output_file):
    bad_code_found = False
    with open(output_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            for pattern in BAD_CODE_PATTERN:
                if re.search(pattern, line):
                    print(f"[!] BAD CODE DETECTED: {line.strip()}")
                    bad_code_found = True

    if bad_code_found:
        quarantine_program(path_to_program)

###############################################################################################################