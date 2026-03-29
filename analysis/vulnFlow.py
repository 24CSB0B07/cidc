import re

def parse_functions(code_lines):
    functions = {}
    i = 0
    while i < len(code_lines):
        line = code_lines[i]
        s = line.strip()

        m = re.match(r'^[\w\*]+\s+(\w+)\s*\(([^)]*)\)\s*\{?', s)
        if m and not s.startswith("//") and not s.startswith("if") \
                and not s.startswith("while") and not s.startswith("for"):

            func_name = m.group(1)
            raw_params = m.group(2).strip()

            params       = []
            param_is_ptr = []
            if raw_params and raw_params != "void" and raw_params != "":
                for param in raw_params.split(","):
                    param  = param.strip()
                    is_ptr = ('*' in param or '&' in param)
                    pname  = re.findall(r'\b(\w+)\s*$', param)
                    if pname:
                        params.append(pname[0])
                        param_is_ptr.append(is_ptr)

            body_lines  = []
            brace_count = 0
            j = i
            while j < len(code_lines):
                if '{' in code_lines[j]:
                    brace_count += code_lines[j].count('{')
                    brace_count -= code_lines[j].count('}')
                    j += 1
                    break
                j += 1

            while j < len(code_lines) and brace_count > 0:
                brace_count += code_lines[j].count('{')
                brace_count -= code_lines[j].count('}')
                if brace_count > 0:
                    body_lines.append((j + 1, code_lines[j]))
                j += 1

            if func_name not in ("if", "while", "for", "switch"):
                functions[func_name] = {
                    "params":       params,
                    "param_is_ptr": param_is_ptr,
                    "body_lines":   body_lines
                }
            i = j
        else:
            i += 1

    return functions


def analyze_lines(lines, taint_table, source_map, prop_map, logs, line_offset=0):
    # PASS 1 – taint sources
    for lineno, line in lines:
        s = line.strip()

        m = re.search(r'scanf\s*\(.*?,\s*&?(\w+)\s*\)', s)
        if m:
            var = m.group(1)
            taint_table[var] = True
            source_map.setdefault(var, f"scanf at line {lineno}")
            logs.append((f"[SOURCE] {var} TAINTED via scanf at line {lineno}\n", "input"))

        m = re.search(r'gets\s*\(\s*(\w+)\s*\)', s)
        if m:
            var = m.group(1)
            taint_table[var] = True
            source_map.setdefault(var, f"gets at line {lineno}")
            logs.append((f"[SOURCE] {var} TAINTED via gets at line {lineno}\n", "input"))

        if "cin" in s and ">>" in s:
            parts = s.split(">>")
            if len(parts) > 1:
                var = parts[1].replace(";", "").strip()
                if var:
                    taint_table[var] = True
                    source_map.setdefault(var, f"cin at line {lineno}")
                    logs.append((f"[SOURCE] {var} TAINTED via cin at line {lineno}\n", "input"))

        m = re.search(r'(\w+)\s*=\s*argv\[\d+\]', s)
        if m:
            var = m.group(1)
            taint_table[var] = True
            source_map.setdefault(var, f"argv at line {lineno}")
            logs.append((f"[SOURCE] {var} TAINTED via argv at line {lineno}\n", "input"))

    # PASS 2 – IR (command_map)
    command_map = {}
    for lineno, line in lines:
        s = line.strip()

        m = re.search(r'strcpy\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)', s)
        if m:
            dest, src = m.groups()
            src = src.strip().replace('"', '')
            command_map.setdefault(dest, []).append(src)

        m = re.search(r'strcat\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)', s)
        if m:
            dest, src = m.groups()
            src = src.strip().replace('"', '')
            command_map.setdefault(dest, []).append(src)

    # PASS 3 – propagation
    changed = True
    while changed:
        changed = False
        for lineno, line in lines:
            s = line.strip()

            m = re.search(r'^(\w+)\s*=\s*(.+);', s)
            if m:
                left, right = m.groups()
                if '(' not in right:
                    for v in re.findall(r'\b\w+\b', right):
                        if v in taint_table and left not in taint_table:
                            taint_table[left] = True
                            prop_map[left] = (v, lineno)
                            logs.append((f"[PROP] {left} <- {v} at line {lineno}\n", "danger"))
                            changed = True

            m = re.search(r'^(?:[\w]+[\s\*]+)+(\w+)\s*=\s*([^=].+);', s)
            if m and '(' not in s.split('=')[0]:
                left, right = m.group(1), m.group(2)
                if '(' not in right:
                    for v in re.findall(r'\b\w+\b', right):
                        if v in taint_table and left not in taint_table:
                            taint_table[left] = True
                            prop_map[left] = (v, lineno)
                            logs.append((f"[PROP] {left} <- {v} (declaration) at line {lineno}\n", "danger"))
                            changed = True

            m = re.search(r'strcpy\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)', s)
            if m:
                dest, src = m.groups()
                if src in taint_table and dest not in taint_table:
                    taint_table[dest] = True
                    prop_map[dest] = (src, lineno)
                    logs.append((f"[PROP] {dest} tainted via strcpy({src}) at line {lineno}\n", "danger"))
                    changed = True

            m = re.search(r'strcat\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)', s)
            if m:
                dest, src = m.groups()
                if src in taint_table and dest not in taint_table:
                    taint_table[dest] = True
                    prop_map[dest] = (src, lineno)
                    logs.append((f"[PROP] {dest} tainted via strcat({src}) at line {lineno}\n", "danger"))
                    changed = True

    return command_map


def detect_sinks(lines, taint_table, source_map, prop_map, command_map, logs, sinks):
    for i, line in lines:
        s = line.strip()

        for sink in sinks:
            m = re.search(rf'{sink}\s*\(\s*(.+?)\s*\)', s)
            if not m:
                continue

            arg = m.group(1)

            if arg.startswith('"') and arg.endswith('"'):
                logs.append((f"[SAFE] {sink}() uses constant string at line {i}\n", "success"))
                continue

            vars_found  = re.findall(r'\b\w+\b', arg)
            severity    = "LOW"
            reason      = ""
            display_var = ""

            if len(vars_found) == 1 and vars_found[0] in taint_table:
                display_var = vars_found[0]
                if vars_found[0] in command_map:
                    severity = "MEDIUM"
                    reason   = "Tainted data used in command construction"
                else:
                    severity = "HIGH"
                    reason   = "Direct tainted input to sink"
            else:
                for v in vars_found:
                    if v in taint_table:
                        display_var = v
                        severity    = "HIGH"
                        reason      = "Tainted data in expression"
                        break

            if display_var == "":
                continue

            explanation = "\nExplanation:\n"
            if display_var in source_map:
                explanation += f"- '{display_var}' comes from {source_map[display_var]}\n"

            temp    = display_var
            visited = set()
            while temp in prop_map and temp not in visited:
                visited.add(temp)
                parent, line_no = prop_map[temp]
                explanation += f"- '{temp}' derived from '{parent}' at line {line_no}\n"
                temp = parent

            explanation += f"- finally used in {sink}() at line {i}\n"

            logs.append((
                f"[{severity}] Command Injection Risk\n"
                f"Line  : {i}\n"
                f"Var   : {display_var}\n"
                f"Reason: {reason}\n"
                f"{explanation}\n",
                "danger"
            ))


def _find_actual_line(body_lines, param, pattern_fn):
    """
    Scan body_lines and return the actual source-file line number
    where pattern_fn(stripped_line, param) matches.
    Falls back to None if not found.
    """
    for lineno, line in body_lines:
        if pattern_fn(line.strip(), param):
            return lineno
    return None


def run_vulnflow_analysis(code_lines):

    taint_table = {}
    source_map  = {}
    prop_map    = {}
    logs        = []
    sinks       = ["system", "popen", "exec"]

    # STEP 0: Parse all function definitions
    functions = parse_functions(code_lines)

    if functions:
        logs.append((f"Detected functions: {', '.join(functions.keys())}\n", "info"))

    # STEP 1: Analyze each function body in isolation
    func_tainted_params = {}

    for fname, fdata in functions.items():
        params       = fdata["params"]
        param_is_ptr = fdata["param_is_ptr"]
        body_lines   = fdata["body_lines"]

        if not body_lines:
            continue

        tainted_param_indices = set()

        internal_taint  = {}
        internal_source = {}
        internal_prop   = {}
        internal_logs   = []
        analyze_lines(body_lines, internal_taint, internal_source, internal_prop, internal_logs)

        # Store internal_source on fdata so we can look up actual line numbers later
        fdata["internal_source"] = internal_source

        for idx, param in enumerate(params):
            if param in internal_taint:
                if idx < len(param_is_ptr) and param_is_ptr[idx]:
                    tainted_param_indices.add(idx)
                else:
                    logs.append((
                        f"[INFO] '{param}' tainted inside {fname}() but passed by value "
                        f"— caller's variable NOT tainted\n",
                        "info"
                    ))

        fdata["taint_flow"] = {}
        fdata["taint_op"]   = {}
        for seed_idx, seed_param in enumerate(params):
            local_taint  = {seed_param: True}
            local_source = {seed_param: f"param '{seed_param}' of {fname}()"}
            local_prop   = {}
            local_logs   = []
            analyze_lines(body_lines, local_taint, local_source, local_prop, local_logs)

            for idx, param in enumerate(params):
                if param in local_taint and idx != seed_idx:
                    fdata["taint_flow"].setdefault(seed_idx, set()).add(idx)

                    op = "assignment"
                    for _, bline in body_lines:
                        bs = bline.strip()
                        if re.search(rf'strcat\s*\(\s*{param}\s*,\s*{seed_param}\s*\)', bs):
                            op = "strcat"
                            break
                        elif re.search(rf'strcpy\s*\(\s*{param}\s*,\s*{seed_param}\s*\)', bs):
                            op = "strcpy"
                            break
                        elif re.search(rf'{param}\s*=.*{seed_param}', bs):
                            op = "assignment"
                            break
                    fdata["taint_op"][(seed_idx, idx)] = op

        func_tainted_params[fname] = tainted_param_indices

    # STEP 2: Build func_sig_lines set
    func_sig_lines = set()
    for fname, fdata in functions.items():
        for i, line in enumerate(code_lines, 1):
            s = line.strip()
            if re.match(rf'^[\w\*]+\s+{fname}\s*\(', s):
                func_sig_lines.add(i)

    # STEP 2b: Analyze full file (skip signature lines)
    all_lines   = [(i + 1, line) for i, line in enumerate(code_lines)
                   if (i + 1) not in func_sig_lines]
    command_map = analyze_lines(all_lines, taint_table, source_map, prop_map, logs)

    # STEP 3: Inter-procedural propagation
    logs.append(("\n[INTER-PROCEDURAL ANALYSIS]\n", "info"))

    logged_inter = set()

    changed = True
    while changed:
        changed = False
        for i, line in enumerate(code_lines, 1):
            s = line.strip()

            if i in func_sig_lines:
                continue

            for fname, fdata in functions.items():
                m = re.search(rf'\b{fname}\s*\(([^)]*)\)', s)
                if not m:
                    continue

                raw_args     = m.group(1)
                args         = [a.strip() for a in raw_args.split(",")]
                param_is_ptr = fdata.get("param_is_ptr", [])
                tainted_indices = func_tainted_params.get(fname, set())

                for idx, arg in enumerate(args):
                    arg_clean = re.sub(
                        r'^(char|int|void|long|short|unsigned|signed|float|double)[\s\*]*', '', arg)
                    arg_clean = arg_clean.lstrip('&').strip()
                    if not re.match(r'^\w+$', arg_clean):
                        continue

                    # Case A: param tainted by internal source (scanf/gets inside function)
                    if idx in tainted_indices:
                        if arg_clean not in taint_table:
                            taint_table[arg_clean] = True
                            param_name = fdata['params'][idx] if idx < len(fdata['params']) else '?'

                            # resolve actual body line from internal_source
                            internal_source = fdata.get("internal_source", {})
                            actual_line_str = internal_source.get(param_name, "")
                            # internal_source entries look like "scanf at line 6"
                            actual_line_match = re.search(r'line (\d+)', actual_line_str)
                            actual_lineno = actual_line_match.group(1) if actual_line_match else str(i)

                            source_map[arg_clean] = (
                                f"user input read inside {fname}() via scanf/gets into param '{param_name}', "
                                f"which maps to '{arg_clean}' at the call site (line {i})"
                            )
                            log_key = ("tainted_by_internal", fname, i, arg_clean)
                            if log_key not in logged_inter:
                                logged_inter.add(log_key)
                                logs.append((
                                    f"[INTER] '{arg_clean}' TAINTED — {fname}() reads user input "
                                    f"into param '{param_name}' at line {actual_lineno}\n",
                                    "danger"
                                ))
                            changed = True

                    # Case B: argument already tainted — propagate via taint_flow
                    elif arg_clean in taint_table:
                        taint_flow = fdata.get("taint_flow", {})

                        if idx in taint_flow:
                            for dest_idx in taint_flow[idx]:
                                if dest_idx < len(args):
                                    dest_arg = args[dest_idx]
                                    dest_arg = re.sub(
                                        r'^(char|int|void|long|short|unsigned|signed|float|double)[\s\*]*',
                                        '', dest_arg)
                                    dest_arg = dest_arg.lstrip('&').strip()
                                    if re.match(r'^\w+$', dest_arg) and dest_arg not in taint_table:
                                        taint_table[dest_arg] = True
                                        dest_param = fdata['params'][dest_idx] if dest_idx < len(fdata['params']) else '?'
                                        op = fdata.get("taint_op", {}).get((idx, dest_idx), "assignment")

                                        # --- FIX: find actual body line for the strcat/strcpy/assignment ---
                                        src_param  = fdata['params'][idx] if idx < len(fdata['params']) else None
                                        actual_op_lineno = None
                                        if src_param and dest_param:
                                            if op == "strcat":
                                                actual_op_lineno = _find_actual_line(
                                                    fdata["body_lines"], dest_param,
                                                    lambda bs, dp=dest_param, sp=src_param:
                                                        bool(re.search(rf'strcat\s*\(\s*{dp}\s*,\s*{sp}\s*\)', bs))
                                                )
                                            elif op == "strcpy":
                                                actual_op_lineno = _find_actual_line(
                                                    fdata["body_lines"], dest_param,
                                                    lambda bs, dp=dest_param, sp=src_param:
                                                        bool(re.search(rf'strcpy\s*\(\s*{dp}\s*,\s*{sp}\s*\)', bs))
                                                )
                                            else:
                                                actual_op_lineno = _find_actual_line(
                                                    fdata["body_lines"], dest_param,
                                                    lambda bs, dp=dest_param, sp=src_param:
                                                        bool(re.search(rf'{dp}\s*=.*{sp}', bs))
                                                )
                                        display_lineno = actual_op_lineno if actual_op_lineno else i

                                        source_map[dest_arg] = (
                                            f"'{arg_clean}' is tainted user input — "
                                            f"it is appended into '{dest_arg}' using {op}() "
                                            f"inside {fname}() at line {display_lineno}"
                                        )
                                        prop_map[dest_arg] = (arg_clean, display_lineno)
                                        log_key = ("taint_flow", fname, i, arg_clean, dest_arg)
                                        if log_key not in logged_inter:
                                            logged_inter.add(log_key)
                                            logs.append((
                                                f"[INTER] '{dest_arg}' TAINTED — tainted '{arg_clean}' "
                                                f"is appended into it via {op}() inside {fname}() at line {display_lineno}\n",
                                                "danger"
                                            ))
                                        changed = True

                        else:
                            dest_indices = set()
                            for flow_dests in taint_flow.values():
                                dest_indices.update(flow_dests)

                            if idx not in dest_indices:
                                log_key = ("passed_into", fname, i, arg_clean)
                                if log_key not in logged_inter:
                                    logged_inter.add(log_key)
                                    logs.append((
                                        f"[INTER] Tainted '{arg_clean}' passed into {fname}() at line {i}\n",
                                        "danger"
                                    ))

                        param_name = fdata['params'][idx] if idx < len(fdata['params']) else None
                        if param_name and fdata["body_lines"]:
                            sink_key = ("body_sink", fname, i, arg_clean)
                            if sink_key not in logged_inter:
                                logged_inter.add(sink_key)
                                body_taint   = {param_name: True}
                                body_source  = {
                                    param_name: f"tainted '{arg_clean}' passed into {fname}() at line {i}"
                                }
                                body_prop    = {}
                                body_logs    = []
                                body_cmd_map = analyze_lines(
                                    fdata["body_lines"], body_taint,
                                    body_source, body_prop, body_logs
                                )
                                detect_sinks(
                                    fdata["body_lines"], body_taint,
                                    body_source, body_prop,
                                    body_cmd_map, logs, sinks
                                )

    # STEP 4: Global sink detection
    logs.append(("\n[SECURITY ANALYSIS]\n", "info"))
    detect_sinks(
        [(i + 1, line) for i, line in enumerate(code_lines)],
        taint_table, source_map, prop_map, command_map, logs, sinks
    )

    # FINAL TAINT TABLE
    logs.append(("\n[FINAL TAINT TABLE]\n", "info"))
    for v in taint_table:
        logs.append((f"  {v} : TAINTED\n", "info"))

    return logs