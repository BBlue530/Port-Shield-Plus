import os
from ProgramMonitoring.Disassembler import disassemble_program
from ProgramMonitoring.HandleBadProgram import quarantine_program
from Variables import disassemblable_extensions, non_disassemblable_extensions, BAD_CODE_PATTERN_BAT, BAD_CODE_PATTERN_SH, BAD_CODE_PATTERN_PY, BAD_CODE_PATTERN_PL, BAD_CODE_PATTERN_JS, BAD_CODE_PATTERN_PHP, BAD_CODE_PATTERN_VBS

###############################################################################################################

def handle_new_program(path_to_program):
    file_extension = os.path.splitext(path_to_program)[1].lower()

    if file_extension in disassemblable_extensions:
        disassemble_program(path_to_program)

    elif file_extension in non_disassemblable_extensions:
        if file_extension == ".bat":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_BAT)
        elif file_extension == ".sh":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_SH)
        elif file_extension == ".py":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_PY)
        elif file_extension == ".pl":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_PL)
        elif file_extension == ".js":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_JS)
        elif file_extension == ".php":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_PHP)
        elif file_extension == ".vbs":
            check_file_bad_patterns(path_to_program, BAD_CODE_PATTERN_VBS)

    else:
        # Will make it send out a alert so it can get reviewed 
        print(f"[!] File: {path_to_program} Unknown extension {file_extension}.")
        quarantine_program(path_to_program)

###############################################################################################################

def check_file_bad_patterns(path_to_program, patterns):
    try:
        with open(path_to_program, 'r', encoding='utf-8') as file:
            file_content = file.read()
            
            for pattern in patterns:
                if pattern.lower() in file_content.lower():
                    print(f"[!] Pattern: {pattern} Found: {path_to_program}")
                    quarantine_program(path_to_program)
                    return
            
            print(f"[i] No patterns found in {path_to_program}")
            return

    except Exception as e:
        print(f"[!] Error reading file: {path_to_program}: {e}")
        quarantine_program(path_to_program)
        return
    
###############################################################################################################