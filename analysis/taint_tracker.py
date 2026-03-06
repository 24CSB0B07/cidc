import re

def run_taint_analysis(code_lines):

    taint_table={}
    command_map={}
    logs=[]

    sinks=["system","popen","exec"]

    # PASS 1: TAINT SOURCES
    for i,line in enumerate(code_lines,1):
        stripped=line.strip()

        match=re.search(r'scanf\s*\(.*?(\w+)\s*\)',stripped)
        if match:
            var=match.group(1)
            taint_table[var]=True
            logs.append((f"[TAINT SOURCE] '{var}' marked TAINTED via scanf at line {i}\n","input"))

        match=re.search(r'gets\s*\(\s*(\w+)\s*\)',stripped)
        if match:
            var=match.group(1)
            taint_table[var]=True
            logs.append((f"[TAINT SOURCE] '{var}' marked TAINTED via gets at line {i}\n","input"))

        if "cin" in stripped and ">>" in stripped:
            parts=stripped.split(">>")
            if len(parts)>1:
                var=parts[1].replace(";","").strip()
                if var:
                    taint_table[var]=True
                    logs.append((f"[TAINT SOURCE] '{var}' marked TAINTED via cin at line {i}\n","input"))

        match=re.search(r'(\w+)\s*=\s*argv',stripped)
        if match:
            var=match.group(1)
            taint_table[var]=True
            logs.append((f"[TAINT SOURCE] '{var}' marked TAINTED via argv at line {i}\n","input"))

    # PASS 2: PROPAGATION + IR
    for i,line in enumerate(code_lines,1):
        stripped=line.strip()

        match=re.search(r'strcpy\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)',stripped)
        if match:
            dest,src=match.groups()
            command_map.setdefault(dest,[])
            command_map[dest].append(src)

            if src.startswith('"'):
                logs.append((f"[IR BUILD] Command variable '{dest}' initialized with literal {src} at line {i}\n","info"))
            else:
                logs.append((f"[IR BUILD] Command variable '{dest}' initialized with variable '{src}' at line {i}\n","info"))

        match=re.search(r'strcat\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)',stripped)
        if match:
            dest,src=match.groups()
            command_map.setdefault(dest,[])
            command_map[dest].append(src)

            if src in taint_table:
                logs.append((f"[IR UPDATE] Tainted component '{src}' added to '{dest}' at line {i}\n","danger"))
            else:
                logs.append((f"[IR UPDATE] Clean component '{src}' added to '{dest}' at line {i}\n","info"))

    #Propagation
    changed=True
    while changed:
        changed=False

        for i,line in enumerate(code_lines,1):
            stripped=line.strip()

            assign_match=re.search(r'^(\w+)\s*=\s*(.+);',stripped)
            if assign_match:
                left=assign_match.group(1)
                right=assign_match.group(2)

                rhs_vars=re.findall(r'\b\w+\b',right)

                for var in rhs_vars:
                    if var in taint_table:
                        if left not in taint_table:
                            taint_table[left]=True
                            logs.append((f"[PROPAGATION] '{left}' becomes TAINTED via '{var}' at line {i}\n","danger"))
                            changed=True

            match=re.search(r'strcpy\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)',stripped)
            if match:
                dest,src=match.groups()
                if src in taint_table:
                    if dest not in taint_table:
                        taint_table[dest]=True
                        logs.append((f"[PROPAGATION] '{dest}' becomes TAINTED via strcpy from '{src}' at line {i}\n","danger"))
                        changed=True

            match=re.search(r'strcat\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)',stripped)
            if match:
                dest,src=match.groups()
                if src in taint_table:
                    if dest not in taint_table:
                        taint_table[dest]=True
                        logs.append((f"[PROPAGATION] '{dest}' becomes TAINTED via strcat from '{src}' at line {i}\n","danger"))
                        changed=True

    # PASS 3: COMMAND ANALYSIS
    logs.append(("\n[COMMAND ANALYSIS]\n","info"))

    for i,line in enumerate(code_lines,1):
        stripped=line.strip()

        for sink in sinks:
            match=re.search(rf'{sink}\s*\(\s*(\w+)',stripped)
            if match:
                arg=match.group(1)

                logs.append(("\n","info"))

                if arg in command_map:
                    if arg in taint_table:
                        logs.append((f"Command '{arg}' contains TAINTED components\n","danger"))
                        logs.append((f"[WARNING]\nPotential Command Injection Risk Detected\nLine: {i}\nReason: Tainted data used in command construction\n","danger"))
                    else:
                        logs.append((f"Command '{arg}' is SAFE (no tainted components)\n","success"))

                elif arg in taint_table:
                    logs.append((f"[HIGH]\nCommand Injection Vulnerability at line {i}\n-> Tainted variable '{arg}' flows into {sink}()\n","danger"))

                else:
                    logs.append((f"{sink}() at line {i} uses non-tainted data\n","success"))

    # FINAL TAINT TABLE
    logs.append(("\nFINAL TAINT TABLE:\n","info"))

    for var in taint_table:
        logs.append((f"{var} : TAINTED\n","info"))

    return logs