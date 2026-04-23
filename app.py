"""
CTF Assembly Lab — Educational
IDA-style Control Flow Graph + CTF mission mode.
Run:   python3 app.py
Visit: http://localhost:8888/
"""

import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Simulator core (same as before)
# ---------------------------------------------------------------------------

REGISTERS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip"]
FLAGS = ["ZF", "SF", "CF", "OF"]

def fmt_hex(n):
    return f"0x{n & 0xFFFFFFFFFFFFFFFF:016X}"

def set_flags(flags, result, bits=64):
    mask = (1 << bits) - 1
    r = result & mask
    flags["ZF"] = 1 if r == 0 else 0
    flags["SF"] = 1 if (r >> (bits - 1)) & 1 else 0
    flags["CF"] = 1 if result < 0 or result > mask else 0
    flags["OF"] = 0

def get_val(regs, op):
    op = op.strip()
    if op.lower() in regs:
        return regs[op.lower()]
    try:
        return int(op, 16) if op.lower().startswith("0x") else int(op)
    except ValueError:
        return 0

def simulate(instructions_text):
    raw_lines = [l.strip() for l in instructions_text.strip().splitlines()]
    lines, label_map = [], {}
    for raw in raw_lines:
        code = raw.split(";")[0].strip()
        if not code:
            continue
        if code.endswith(":"):
            label_map[code[:-1].lower()] = len(lines)
        else:
            lines.append(code)

    regs = {r: 0 for r in REGISTERS}
    regs["rsp"] = 0x7FFF0000
    regs["rbp"] = 0x7FFF0000
    flags = {f: 0 for f in FLAGS}
    stack = []
    steps = []
    ip = 0

    def snap(ip, line, note="", highlight=None):
        steps.append({
            "ip": ip, "line": line, "note": note,
            "highlight": highlight or [],
            "regs": {k: fmt_hex(v) for k, v in regs.items()},
            "regs_raw": dict(regs),
            "flags": dict(flags),
            "stack": list(stack),
        })

    MAX_STEPS = 500
    step_count = 0
    while 0 <= ip < len(lines) and step_count < MAX_STEPS:
        step_count += 1
        raw = lines[ip]
        parts = raw.split(None, 1)
        mn = parts[0].lower()
        args = [a.strip() for a in (parts[1] if len(parts) > 1 else "").split(",")]
        note, hl, next_ip = "", [], ip + 1

        if mn == "mov":
            dst, val = args[0].lower(), get_val(regs, args[1])
            regs[dst] = val & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst} = {fmt_hex(val)}", [dst]
        elif mn == "add":
            dst = args[0].lower(); res = regs[dst] + get_val(regs, args[1])
            set_flags(flags, res); regs[dst] = res & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst} = {fmt_hex(regs[dst])}", [dst]
        elif mn == "sub":
            dst = args[0].lower(); res = regs[dst] - get_val(regs, args[1])
            set_flags(flags, res); regs[dst] = res & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst} = {fmt_hex(regs[dst])}", [dst]
        elif mn == "inc":
            dst = args[0].lower(); res = regs[dst] + 1
            set_flags(flags, res); regs[dst] = res & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst}++ = {fmt_hex(regs[dst])}", [dst]
        elif mn == "dec":
            dst = args[0].lower(); res = regs[dst] - 1
            set_flags(flags, res); regs[dst] = res & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst}-- = {fmt_hex(regs[dst])}", [dst]
        elif mn == "and":
            dst = args[0].lower(); val = get_val(regs, args[1])
            regs[dst] &= val; set_flags(flags, regs[dst])
            note, hl = f"{dst} = {fmt_hex(regs[dst])}", [dst]
        elif mn == "or":
            dst = args[0].lower(); val = get_val(regs, args[1])
            regs[dst] |= val; set_flags(flags, regs[dst])
            note, hl = f"{dst} = {fmt_hex(regs[dst])}", [dst]
        elif mn == "xor":
            dst = args[0].lower(); val = get_val(regs, args[1])
            regs[dst] ^= val; set_flags(flags, regs[dst])
            note, hl = f"{dst} = {fmt_hex(regs[dst])}", [dst]
        elif mn == "shl":
            dst = args[0].lower(); amt = get_val(regs, args[1]) & 0x3F
            regs[dst] = (regs[dst] << amt) & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst} <<= {amt}", [dst]
        elif mn == "shr":
            dst = args[0].lower(); amt = get_val(regs, args[1]) & 0x3F
            regs[dst] = (regs[dst] >> amt) & 0xFFFFFFFFFFFFFFFF
            note, hl = f"{dst} >>= {amt}", [dst]
        elif mn == "cmp":
            a, b = get_val(regs, args[0]), get_val(regs, args[1])
            set_flags(flags, a - b)
            note = f"compare {fmt_hex(a)} vs {fmt_hex(b)} → ZF={flags['ZF']} SF={flags['SF']}"
        elif mn == "test":
            a, b = get_val(regs, args[0]), get_val(regs, args[1])
            set_flags(flags, a & b)
            note = f"test {fmt_hex(a)} & {fmt_hex(b)} → ZF={flags['ZF']}"
        elif mn == "push":
            val = get_val(regs, args[0])
            regs["rsp"] = (regs["rsp"] - 8) & 0xFFFFFFFFFFFFFFFF
            stack.append({"addr": fmt_hex(regs["rsp"]), "val": fmt_hex(val), "label": args[0]})
            note, hl = f"push {fmt_hex(val)}", ["rsp"]
        elif mn == "pop":
            dst = args[0].lower()
            if stack: regs[dst] = int(stack.pop()["val"], 16)
            regs["rsp"] = (regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
            note, hl = f"pop → {dst} = {fmt_hex(regs[dst])}", [dst, "rsp"]
        elif mn == "jmp":
            tgt = args[0].lower()
            if tgt in label_map:
                next_ip = label_map[tgt]; note = f"jump → {tgt}"
            else:
                note = f"jump {tgt} (unresolved)"; next_ip = len(lines)
        elif mn in ("je", "jz"):
            tgt = args[0].lower(); taken = flags["ZF"] == 1
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — ZF={flags['ZF']} (jump if equal/zero)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn in ("jne", "jnz"):
            tgt = args[0].lower(); taken = flags["ZF"] == 0
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — ZF={flags['ZF']} (jump if not equal)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "jl":
            tgt = args[0].lower(); taken = flags["SF"] != flags["OF"]
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — (jump if less)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "jg":
            tgt = args[0].lower(); taken = flags["ZF"] == 0 and flags["SF"] == flags["OF"]
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — (jump if greater)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "jle":
            tgt = args[0].lower(); taken = flags["ZF"] == 1 or flags["SF"] != flags["OF"]
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — (jump if less or equal)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "jge":
            tgt = args[0].lower(); taken = flags["SF"] == flags["OF"]
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — (jump if greater or equal)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "ja":
            tgt = args[0].lower(); taken = flags["CF"] == 0 and flags["ZF"] == 0
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — (jump if above)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "jb":
            tgt = args[0].lower(); taken = flags["CF"] == 1
            note = f"{'✓ TAKEN' if taken else '✗ not taken'} — (jump if below)"
            if taken and tgt in label_map: next_ip = label_map[tgt]
        elif mn == "call":
            tgt = args[0].lower(); ret_addr = ip + 1
            regs["rsp"] = (regs["rsp"] - 8) & 0xFFFFFFFFFFFFFFFF
            stack.append({"addr": fmt_hex(regs["rsp"]), "val": fmt_hex(ret_addr), "label": f"ret→{ret_addr}"})
            if tgt in label_map:
                next_ip = label_map[tgt]; note = f"call {tgt} (return addr saved)"
            else:
                note = f"call {tgt} (external)"
            hl = ["rsp"]
        elif mn == "ret":
            if stack:
                ret_addr = int(stack.pop()["val"], 16)
                regs["rsp"] = (regs["rsp"] + 8) & 0xFFFFFFFFFFFFFFFF
                next_ip = ret_addr; note = f"return → line {ret_addr}"
            else:
                note = "return — stack empty"; next_ip = len(lines)
            hl = ["rsp", "rip"]
        elif mn == "nop":
            note = "no operation"
        else:
            note = f"unknown: {mn}"

        regs["rip"] = ip
        snap(ip, raw, note, hl)
        ip = next_ip

    return {"steps": steps, "lines": lines, "labels": label_map, "total": len(steps)}


def build_cfg(instructions_text):
    """
    Build a Control Flow Graph from assembly.
    Returns blocks: [ { id, lines: [{idx, text}], successors: [{to, type}] } ]
    """
    raw_lines = [l.strip() for l in instructions_text.strip().splitlines()]
    lines, label_map, line_labels = [], {}, {}

    for raw in raw_lines:
        code = raw.split(";")[0].strip()
        if not code:
            continue
        if code.endswith(":"):
            lname = code[:-1].lower()
            label_map[lname] = len(lines)
            line_labels[len(lines)] = lname
        else:
            lines.append(code)

    if not lines:
        return {"blocks": [], "edges": []}

    # Find block leaders (start of each basic block)
    leaders = {0}
    JUMP_MN = {"jmp","je","jz","jne","jnz","jl","jg","jle","jge","ja","jb","call"}
    for i, line in enumerate(lines):
        mn = line.split()[0].lower() if line.split() else ""
        if mn in JUMP_MN or mn == "ret":
            if i + 1 < len(lines):
                leaders.add(i + 1)
            args = [a.strip() for a in line.split(None, 1)[1].split(",")] if len(line.split(None, 1)) > 1 else []
            if args and args[0].lower() in label_map:
                leaders.add(label_map[args[0].lower()])

    leaders = sorted(leaders)

    # Build blocks
    blocks = []
    leader_to_block = {}
    for idx, start in enumerate(leaders):
        end = leaders[idx + 1] if idx + 1 < len(leaders) else len(lines)
        block_lines = []
        for li in range(start, end):
            label = line_labels.get(li, "")
            block_lines.append({"idx": li, "text": lines[li], "label": label})
        bid = f"B{idx}"
        leader_to_block[start] = bid
        blocks.append({"id": bid, "start": start, "end": end, "lines": block_lines, "successors": []})

    # Add edges
    edges = []
    for block in blocks:
        last = block["lines"][-1] if block["lines"] else None
        if not last:
            continue
        parts = last["text"].split(None, 1)
        mn = parts[0].lower()
        args = [a.strip() for a in parts[1].split(",")] if len(parts) > 1 else []
        tgt_label = args[0].lower() if args else ""
        tgt_line = label_map.get(tgt_label)
        tgt_block = leader_to_block.get(tgt_line) if tgt_line is not None else None

        if mn == "jmp":
            if tgt_block:
                block["successors"].append({"to": tgt_block, "type": "jmp"})
                edges.append({"from": block["id"], "to": tgt_block, "type": "jmp"})
        elif mn in ("je","jz","jne","jnz","jl","jg","jle","jge","ja","jb"):
            # conditional: true branch (green) + false branch (red)
            if tgt_block:
                block["successors"].append({"to": tgt_block, "type": "true"})
                edges.append({"from": block["id"], "to": tgt_block, "type": "true"})
            fall = leader_to_block.get(block["end"])
            if fall:
                block["successors"].append({"to": fall, "type": "false"})
                edges.append({"from": block["id"], "to": fall, "type": "false"})
        elif mn == "ret":
            block["successors"].append({"to": None, "type": "ret"})
        elif mn == "call":
            fall = leader_to_block.get(block["end"])
            if fall:
                block["successors"].append({"to": fall, "type": "call"})
                edges.append({"from": block["id"], "to": fall, "type": "call"})
        else:
            fall = leader_to_block.get(block["end"])
            if fall:
                block["successors"].append({"to": fall, "type": "fall"})
                edges.append({"from": block["id"], "to": fall, "type": "fall"})

    return {"blocks": blocks, "edges": edges, "label_map": label_map}


# ---------------------------------------------------------------------------
# CTF Missions
# ---------------------------------------------------------------------------

MISSIONS = [
    {
        "id": 1,
        "title": "Mission 1 — The Secret Password",
        "difficulty": "Beginner",
        "story": """A program checks if you know the secret password.
The password is a number stored in a register.
<br><br>
🎯 <b>Your goal:</b> Step through the code and find what value <code>rax</code> must equal to pass the check.
<br><br>
💡 <b>Hint:</b> Watch the <b>CMP</b> instruction — it compares two values. If they match, <b>ZF=1</b> and the jump is taken to <code>access_granted</code>.""",
        "answer": "0x539",
        "flag": "FLAG{rax_equals_0x539}",
        "flag_hint": "Submit the flag in the usual format, for example: FLAG{example_flag}",
        "win_condition": {"type": "reach_label", "label": "access_granted"},
        "code": """; === PASSWORD CHECK ===
; The program loads the secret password and compares
; it against your input (stored in rbx)

mov rax, 0x539       ; secret password loaded
mov rbx, 0x111       ; wrong input on purpose — change this
cmp rax, rbx         ; are they equal?
jne access_denied    ; jump if NOT equal
access_granted:
mov rcx, 1           ; rcx=1 means SUCCESS
jmp done
access_denied:
mov rcx, 0           ; rcx=0 means FAIL
done:
nop"""
    },
    {
        "id": 2,
        "title": "Mission 2 — The Loop Counter",
        "difficulty": "Beginner",
        "story": """A program runs a loop, but the default counter is wrong.
Simply stepping shows the failure path.
<br><br>
🎯 <b>Your goal:</b> Figure out what the loop counter should be, then edit the code so execution reaches <code>unlocked</code>.
<br><br>
💡 <b>Hint:</b> Watch how <code>rax</code> changes each iteration. The correct counter produces the target sum checked at the end.""",
        "answer": "5,15",
        "flag": "FLAG{loop_fixed_count_5_rax_15}",
        "flag_hint": "Submit the flag in the usual format, for example: FLAG{example_flag}",
        "win_condition": {"type": "reach_label", "label": "unlocked"},
        "code": """; === LOOP COUNTER CHALLENGE ===
; The default counter is wrong on purpose.
; You need the loop to produce exactly rax = 15.

mov rcx, 6           ; wrong on purpose — patch this
mov rax, 0           ; accumulator
loop_body:
add rax, rcx         ; rax += rcx
dec rcx              ; rcx--
cmp rcx, 0           ; is counter zero?
jne loop_body        ; keep looping if not
cmp rax, 15          ; target sum
jne locked
unlocked:
nop
jmp done
locked:
nop
done:
nop"""
    },
    {
        "id": 3,
        "title": "Mission 3 — The XOR Cipher",
        "difficulty": "Intermediate",
        "story": """A secret message has been XOR-encrypted, but one key is wrong on purpose.
If you only step through it, you should land on the failure path.
<br><br>
🎯 <b>Your goal:</b> Recover the correct second XOR key, patch it, and make execution reach <code>decrypted</code>.
<br><br>
💡 <b>Hint:</b> XOR is reversible. Compare the observed value with the target check to infer the missing key.""",
        "answer": "0xca96,0x1337",
        "flag": "FLAG{xor_second_key_0xCA96_result_0x1337}",
        "flag_hint": "Submit the flag in the usual format, for example: FLAG{example_flag}",
        "win_condition": {"type": "reach_label", "label": "decrypted"},
        "code": """; === XOR CIPHER ===
; One key is wrong on purpose.
; You need the final value to become 0x1337.

mov rax, 0xCFBA      ; encrypted message
mov rbx, 0xDEAD      ; XOR key (first pass)
xor rax, rbx         ; decrypt step 1
mov rbx, 0xCA97      ; wrong on purpose — patch this
xor rax, rbx         ; decrypt step 2
cmp rax, 0x1337      ; target plaintext
jne fail
decrypted:
nop
jmp done
fail:
mov rax, 0xDEAD
done:
nop"""
    },
    {
        "id": 4,
        "title": "Mission 4 — Bypass the License Check",
        "difficulty": "Intermediate",
        "story": """A program validates a license key using multiple checks.
Each check must pass to reach the <code>licensed</code> label.
<br><br>
🎯 <b>Your goal:</b> Understand what each check does.
Can you reach <code>licensed:</code>?
<br><br>
💡 <b>Hint:</b> There are <b>3 checks</b> in sequence.
All three must pass. Watch the CFG — each branch leads somewhere different.""",
        "answer": "1,0x10,0xff",
        "flag": "FLAG{three_checks_all_passed}",
        "flag_hint": "Submit the flag in the usual format, for example: FLAG{example_flag}",
        "win_condition": {"type": "reach_label", "label": "licensed"},
        "code": """; === LICENSE KEY VALIDATOR ===
; Three checks must ALL pass

mov rdi, 1           ; license flag (must be 1)
mov rsi, 0x0F        ; wrong on purpose — must be >= 16
mov rdx, 0xFF        ; checksum (must be 255)

; Check 1: license flag must be 1
cmp rdi, 1
jne invalid
; Check 2: version must be >= 16
cmp rsi, 0x10
jl invalid
; Check 3: checksum must equal 0xFF
cmp rdx, 0xFF
jne invalid
licensed:
mov rax, 0xACCE55    ; access granted!
jmp done
invalid:
mov rax, 0xDEAD      ; access denied
done:
nop"""
    },
    {
        "id": 5,
        "title": "Mission 5 — Stack Smash",
        "difficulty": "Advanced",
        "story": """This one is meant to feel closer to a small reversing puzzle.
The stack is used across multiple calls, and the default argument is wrong.
<br><br>
🎯 <b>Your goal:</b> Trace the CALL / RET flow, understand what value the function really wants, then patch the input so execution reaches <code>returned</code> with the correct result.
<br><br>
💡 <b>Hint:</b> Follow both helper functions. One transforms the argument, and the other checks whether the transformed value is acceptable.""",
        "answer": "0x15,0x2a",
        "flag": "FLAG{stack_path_arg_0x15_returns_0x2A}",
        "flag_hint": "Submit the flag in the usual format, for example: FLAG{example_flag}",
        "win_condition": {"type": "reach_label", "label": "returned"},
        "code": """; === STACK & FUNCTION CALL ===
; The default argument is wrong on purpose.
; You need the final return value to become 0x2A.

mov rdi, 0x14        ; wrong on purpose — patch this
call stage_one
cmp rax, 0x2A
jne fail
returned:
nop
jmp end

stage_one:
push rbp
mov rbp, rsp
call stage_two
pop rbp
ret

stage_two:
push rbp
mov rbp, rsp
mov rax, rdi         ; start with input
add rax, 3           ; bias
cmp rax, 0x18        ; must become 0x18 here
jne bad_path
add rax, 0x12        ; 0x18 + 0x12 = 0x2A
pop rbp
ret

bad_path:
mov rax, 0xDEAD
pop rbp
ret

fail:
mov rax, 0xBEEF
end:
nop"""
    },
]



# ---------------------------------------------------------------------------
# Answer / flag helpers
# ---------------------------------------------------------------------------

def normalize_answer(v):
    return "".join(str(v).strip().lower().split())

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTF Assembly Lab</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap');
:root{
  --bg:#0a0c10;--bg2:#111318;--bg3:#1a1d24;--bg4:#0f1117;
  --bd:#2a2d35;--bd2:#383c48;
  --tx:#cdd6f4;--mu:#6c7086;
  --gr:#a6e3a1;--gd:#1e3a2a;--gb:#2a5a3a;
  --bl:#89b4fa;--bld:#1a2a4a;--blb:#2a3a6a;
  --yl:#f9e2af;--yd:#3a2e10;
  --rd:#f38ba8;--rdd:#3a1020;--rdb:#6a2a2a;
  --pu:#cba6f7;--tl:#94e2d5;--or:#fab387;
  --pk:#f5c2e7;
  --mono:'JetBrains Mono',monospace;
  --sans:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--mono);background:var(--bg);color:var(--tx);height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* ── TOP BAR ── */
.topbar{display:flex;align-items:center;gap:12px;padding:.5rem 1rem;background:var(--bg2);border-bottom:1px solid var(--bd);flex-shrink:0}
.logo{font-size:.85rem;font-weight:700;color:var(--bl);letter-spacing:.06em;white-space:nowrap}
.logo span{color:var(--mu);font-weight:400}
.mission-tabs{display:flex;gap:4px;flex:1;overflow-x:auto}
.mtab{font-family:var(--sans);font-size:.72rem;padding:.3rem .75rem;border-radius:4px;border:1px solid var(--bd);background:transparent;color:var(--mu);cursor:pointer;white-space:nowrap;transition:all .15s}
.mtab:hover{color:var(--tx);border-color:var(--bd2)}
.mtab.active{background:var(--bld);color:var(--bl);border-color:var(--blb)}
.mtab .diff{font-size:.6rem;margin-left:4px;opacity:.6}
.badge{font-size:.62rem;padding:2px 7px;border-radius:3px;font-family:var(--mono);white-space:nowrap}
.bg-gr{background:var(--gd);color:var(--gr);border:1px solid var(--gb)}
.bg-bl{background:var(--bld);color:var(--bl);border:1px solid var(--blb)}
.bg-rd{background:var(--rdd);color:var(--rd);border:1px solid var(--rdb)}
.bg-yl{background:var(--yd);color:var(--yl);border:1px solid #5a4a20}

/* ── MAIN LAYOUT ── */
.workspace{display:grid;grid-template-columns:300px 1fr 260px;flex:1;min-height:0;overflow:hidden}

/* ── LEFT: Mission + Editor ── */
.left{display:flex;flex-direction:column;border-right:1px solid var(--bd);overflow:hidden}
.mission-card{padding:.9rem 1rem;background:var(--bg2);border-bottom:1px solid var(--bd);font-family:var(--sans);flex-shrink:0}
.mission-title{font-size:.9rem;font-weight:600;color:var(--tx);margin-bottom:.4rem;display:flex;align-items:center;gap:8px}
.mission-story{font-size:.75rem;color:var(--mu);line-height:1.65;margin-bottom:.7rem}
.mission-story b{color:var(--yl)}
.mission-story code{font-family:var(--mono);color:var(--tl);font-size:.72rem}
.flag-box{background:var(--bg3);border:1px solid var(--bd2);border-radius:5px;padding:.5rem .7rem;font-size:.7rem}
.flag-label{color:var(--mu);margin-bottom:3px;font-size:.62rem;text-transform:uppercase;letter-spacing:.06em}
.flag-input{display:flex;gap:5px;margin-top:4px}
.flag-input input{flex:1;background:var(--bg);border:1px solid var(--bd2);border-radius:3px;padding:.3rem .5rem;color:var(--tx);font-family:var(--mono);font-size:.68rem;outline:none}
.flag-input input:focus{border-color:var(--bl)}
.flag-input button{background:var(--gd);color:var(--gr);border:1px solid var(--gb);border-radius:3px;padding:.3rem .6rem;cursor:pointer;font-family:var(--mono);font-size:.68rem}
.flag-input button:hover{background:#2a4a36}
.flag-ok{color:var(--gr);font-size:.72rem;margin-top:4px;display:none}
.flag-no{color:var(--rd);font-size:.72rem;margin-top:4px;display:none}

.ph{padding:.45rem .8rem;background:var(--bg2);border-bottom:1px solid var(--bd);font-size:.62rem;color:var(--mu);letter-spacing:.1em;text-transform:uppercase;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
textarea{flex:1;background:var(--bg4);border:none;resize:none;color:var(--tx);font-family:var(--mono);font-size:.75rem;line-height:1.7;padding:.8rem;outline:none;min-height:0}

/* controls */
.ctrl{padding:.55rem .8rem;border-top:1px solid var(--bd);background:var(--bg2);display:flex;gap:6px;align-items:center;flex-shrink:0}
button.run{background:var(--gd);color:var(--gr);border:1px solid var(--gb);border-radius:4px;padding:.32rem .7rem;cursor:pointer;font-family:var(--mono);font-size:.72rem;transition:all .12s}
button.run:hover{background:#2a4a36}
button.step{background:var(--bld);color:var(--bl);border:1px solid var(--blb);border-radius:4px;padding:.32rem .7rem;cursor:pointer;font-family:var(--mono);font-size:.72rem}
button.step:hover{background:#22345a}
button.plain{background:var(--bg3);color:var(--mu);border:1px solid var(--bd);border-radius:4px;padding:.32rem .7rem;cursor:pointer;font-family:var(--mono);font-size:.72rem}
button.plain:hover{color:var(--tx)}
button:disabled{opacity:.35;cursor:not-allowed}
.sc{margin-left:auto;font-size:.65rem;color:var(--mu)}

/* ── CENTER: CFG ── */
.center{display:flex;flex-direction:column;overflow:hidden;background:var(--bg4)}
.cfg-wrap{flex:1;overflow:auto;position:relative;min-height:0}
#cfg-canvas{display:block}

/* CFG block styles (SVG foreignObject doesn't work well cross-browser, use overlay divs) */
.cfg-container{position:relative}
.cfg-block{
  position:absolute;
  background:var(--bg2);
  border:1px solid var(--bd2);
  border-radius:6px;
  overflow:hidden;
  font-family:var(--mono);
  font-size:.7rem;
  min-width:180px;
  max-width:240px;
  transition:border-color .2s,box-shadow .2s;
}
.cfg-block.active-block{border-color:var(--bl);box-shadow:0 0 0 2px rgba(137,180,250,.25)}
.cfg-block.visited{border-color:#383c48}
.cfg-block-header{padding:.28rem .55rem;background:var(--bg3);border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:5px;font-size:.62rem;color:var(--mu)}
.cfg-block-header .bid{color:var(--pu)}
.cfg-block-header .blabel{color:var(--yl);font-size:.6rem}
.cfg-line{padding:.18rem .55rem;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-bottom:1px solid rgba(255,255,255,.03);cursor:default}
.cfg-line:last-child{border-bottom:none}
.cfg-line.active-line{background:rgba(137,180,250,.15);color:var(--bl)}
.cfg-line .mnemonic{color:var(--tl)}
.cfg-line .operands{color:var(--tx)}
.cfg-line .comment{color:var(--mu);font-size:.65rem}
.cfg-line.jump-line .mnemonic{color:var(--yl)}
.cfg-line.ret-line .mnemonic{color:var(--rd)}

/* note bar */
.note-bar{padding:.4rem .8rem;background:var(--bg2);border-top:1px solid var(--bd);font-size:.72rem;min-height:28px;display:flex;align-items:center;gap:6px;flex-shrink:0}
.note-lbl{color:var(--mu);font-size:.6rem;white-space:nowrap}
#note-text{color:var(--yl)}

/* ── RIGHT: Registers + Stack ── */
.right{display:flex;flex-direction:column;border-left:1px solid var(--bd);overflow:hidden}
.reg-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px;padding:.6rem;overflow-y:auto;flex:1}
.rc{background:var(--bg3);border:1px solid var(--bd);border-radius:4px;padding:.35rem .5rem;transition:border-color .15s,background .15s}
.rc.ch{border-color:var(--bl);background:var(--bld)}
.rc.hi{border-color:var(--yl);background:var(--yd)}
.rn{font-size:.58rem;color:var(--mu);letter-spacing:.04em;margin-bottom:1px}
.rv{font-size:.68rem;color:var(--tl);font-weight:500;word-break:break-all}
.rc.hi .rv{color:var(--yl)}

.flags-row{display:flex;gap:4px;padding:.5rem .6rem;border-top:1px solid var(--bd);border-bottom:1px solid var(--bd);flex-shrink:0}
.fl{flex:1;background:var(--bg3);border:1px solid var(--bd);border-radius:4px;padding:.3rem .4rem;text-align:center;transition:all .15s}
.fl.fset{background:var(--gd);border-color:var(--gb)}
.fl-name{font-size:.58rem;color:var(--mu)}
.fl-val{font-size:.9rem;font-weight:700}
.fset .fl-val{color:var(--gr)}
.funset .fl-val{color:var(--bd2)}

.stack-area{display:flex;flex-direction:column;overflow:hidden;flex:0 0 180px;border-top:1px solid var(--bd)}
.stack-list{flex:1;overflow-y:auto;padding:.4rem;display:flex;flex-direction:column;gap:3px}
.se{background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:.28rem .5rem;font-size:.63rem}
.se:first-child{border-color:var(--or);background:#2a1e10}
.sa{color:var(--mu);font-size:.58rem}.sv{color:var(--or);font-weight:500}.sl{color:var(--mu);font-size:.55rem}
.se-empty{color:var(--mu);font-size:.68rem;padding:.6rem;text-align:center}

/* win overlay */
.win-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.win-overlay.show{display:flex}
.win-card{background:var(--bg2);border:1px solid var(--gr);border-radius:12px;padding:2rem;max-width:400px;width:90%;text-align:center}
.win-icon{font-size:3rem;margin-bottom:.8rem}
.win-title{font-size:1.3rem;font-weight:700;color:var(--gr);margin-bottom:.5rem;font-family:var(--sans)}
.win-flag{background:var(--bg3);border:1px solid var(--gb);border-radius:6px;padding:.7rem 1rem;font-size:.8rem;color:var(--gr);margin:.8rem 0;word-break:break-all}
.win-btn{background:var(--gd);color:var(--gr);border:1px solid var(--gb);border-radius:6px;padding:.5rem 1.2rem;cursor:pointer;font-family:var(--mono);font-size:.8rem;margin-top:.5rem}
.win-btn:hover{background:#2a4a36}

::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:2px}
</style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <div class="logo">CTF <span>Assembly Lab</span></div>
  <div class="mission-tabs" id="missionTabs"></div>
  <span class="badge bg-bl" id="diffBadge">Beginner</span>
</div>

<!-- WORKSPACE -->
<div class="workspace">

  <!-- LEFT -->
  <div class="left">
    <div class="mission-card" id="missionCard">
      <div class="mission-title">
        <span id="missionTitle">Mission</span>
      </div>
      <div class="mission-story" id="missionStory"></div>
      <div class="flag-box">
        <div class="flag-label">Submit Answer</div>
        <div style="color:var(--mu);font-size:.65rem;margin-bottom:4px" id="flagHint"></div>
        <div class="flag-input">
          <input type="text" id="flagInput" placeholder="FLAG{...}">
          <button onclick="checkFlag()">Submit</button>
        </div>
        <div class="flag-ok" id="flagOk">✓ Correct! Flag generated.</div>
        <div class="flag-no" id="flagNo">✗ Not quite. Analyze the code again.</div>
      </div>
    </div>
    <div class="ph">
      Assembly Code
      <span id="winIndicator"></span>
    </div>
    <textarea id="code" spellcheck="false"></textarea>
    <div class="ctrl">
      <button class="run" id="bRun">▶ Run</button>
      <button class="step" id="bStep" disabled>Step →</button>
      <button class="plain" id="bBack" disabled>← Back</button>
      <button class="plain" id="bReset" disabled>Reset</button>
      <span class="sc" id="sc"></span>
    </div>
  </div>

  <!-- CENTER: CFG -->
  <div class="center">
    <div class="ph">
      Control Flow Graph
      <span style="font-size:.6rem;color:var(--mu)">
        <span style="color:var(--gr)">━</span> true/jmp &nbsp;
        <span style="color:var(--rd)">━</span> false &nbsp;
        <span style="color:var(--mu)">━</span> fall-through
      </span>
    </div>
    <div class="cfg-wrap" id="cfgWrap">
      <div style="color:var(--mu);font-size:.75rem;padding:2rem;font-family:var(--sans)">
        Press ▶ Run to generate the Control Flow Graph...
      </div>
    </div>
    <div class="note-bar">
      <span class="note-lbl">STEP</span>
      <span id="note-text">—</span>
    </div>
  </div>

  <!-- RIGHT -->
  <div class="right">
    <div class="ph">Registers</div>
    <div class="reg-grid" id="regGrid"></div>
    <div class="flags-row" id="flagsRow"></div>
    <div class="stack-area">
      <div class="ph">Stack</div>
      <div class="stack-list" id="stackList"><div class="se-empty">empty</div></div>
    </div>
  </div>

</div>

<!-- WIN OVERLAY -->
<div class="win-overlay" id="winOverlay">
  <div class="win-card">
    <div class="win-icon">🏆</div>
    <div class="win-title" id="winTitle">Target Reached</div>
    <div style="color:var(--mu);font-size:.82rem;font-family:var(--sans);margin-bottom:.5rem" id="winSubtitle">You reached the target path. Good — but no flag is revealed until you submit the right answer:</div>
    <div class="win-flag" id="winFlag">Analyze → patch → submit</div>
    <div style="color:var(--mu);font-size:.75rem;font-family:var(--sans)">Stepping alone should not solve the mission.</div>
    <button class="win-btn" onclick="closeWin()">Continue →</button>
  </div>
</div>

<script>
const MISSIONS = __MISSIONS_JSON__;
const REGS = ['rax','rbx','rcx','rdx','rsi','rdi','rsp','rbp','rip'];
const $ = id => document.getElementById(id);

let steps=[], curStep=-1, curMission=null, cfg=null, winShown=false;

// ── Mission tabs ──
function buildTabs(){
  const el=$('missionTabs');
  MISSIONS.forEach(m=>{
    const b=document.createElement('button');
    b.className='mtab';b.dataset.id=m.id;
    b.innerHTML=`M${m.id} <span class="diff">${m.difficulty}</span>`;
    b.onclick=()=>loadMission(m.id);
    el.appendChild(b);
  });
}

function loadMission(id){
  const m=MISSIONS.find(x=>x.id===id);
  if(!m)return;
  curMission=m;winShown=false;
  $('missionTitle').textContent=m.title;
  $('missionStory').innerHTML=m.story;
  $('flagHint').textContent='Hint: '+m.flag_hint;
  $('code').value=m.code;
  $('flagInput').value='';
  $('flagOk').style.display='none';
  $('flagNo').style.display='none';
  $('winIndicator').textContent='';
  // difficulty badge
  const diff=m.difficulty;
  const db=$('diffBadge');
  db.textContent=diff;
  db.className='badge '+(diff==='Beginner'?'bg-gr':diff==='Intermediate'?'bg-yl':'bg-rd');
  // active tab
  document.querySelectorAll('.mtab').forEach(t=>{
    t.classList.toggle('active',parseInt(t.dataset.id)===id);
  });
  resetState();
}

// ── Flag check ──
async function checkFlag(){
  const answer=$('flagInput').value.trim();
  const r=await fetch('/check_flag',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mission_id:curMission.id,answer})
  });
  const d=await r.json();
  const ok=!!d.ok;
  $('flagOk').style.display=ok?'block':'none';
  $('flagNo').style.display=ok?'none':'block';
  if(ok){
    $('flagOk').textContent='✓ Correct! '+d.flag;
    $('winTitle').textContent='Mission Complete!';
    $('winSubtitle').textContent='Good job. Here is your real flag:';
    $('winFlag').textContent=d.flag;
    $('winOverlay').classList.add('show');
  } else {
    $('flagNo').textContent='✗ Not quite. Analyze the code again.';
  }
}

function closeWin(){$('winOverlay').classList.remove('show')}

// ── Run / Step / Reset ──
$('bRun').onclick=run;
$('bStep').onclick=()=>go(curStep+1);
$('bBack').onclick=()=>go(curStep-1);
$('bReset').onclick=()=>{resetState();$('note-text').textContent='—'};

async function run(){
  const code=$('code').value.trim();if(!code)return;
  resetState();
  $('bRun').disabled=true;$('bRun').textContent='...';
  try{
    // Simulate
    const r1=await fetch('/simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
    const d1=await r1.json();
    if(d1.error){$('note-text').textContent='Error: '+d1.error;$('note-text').style.color='var(--rd)';return;}
    steps=d1.steps;

    // CFG
    const r2=await fetch('/cfg',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
    cfg=await r2.json();

    renderCFG();
    enableCtrl();
    $('note-text').textContent=`${steps.length} steps — use Step → or click CFG blocks`;
    $('note-text').style.color='var(--mu)';
    go(0);
  }catch(e){$('note-text').textContent='Error: '+e.message;}
  finally{$('bRun').disabled=false;$('bRun').textContent='▶ Run';}
}

function enableCtrl(){$('bStep').disabled=$('bBack').disabled=$('bReset').disabled=false;}

function resetState(){
  steps=[];curStep=-1;cfg=null;winShown=false;
  $('cfgWrap').innerHTML='<div style="color:var(--mu);font-size:.75rem;padding:2rem;font-family:var(--sans)">Press ▶ Run to generate the Control Flow Graph...</div>';
  $('regGrid').innerHTML='';$('flagsRow').innerHTML='';
  $('stackList').innerHTML='<div class="se-empty">empty</div>';
  $('sc').textContent='';$('note-text').textContent='—';$('note-text').style.color='var(--yl)';
  $('bStep').disabled=$('bBack').disabled=$('bReset').disabled=true;
}

// ── Go to step ──
function go(idx){
  if(!steps.length)return;
  idx=Math.max(0,Math.min(steps.length-1,idx));
  curStep=idx;
  const s=steps[idx],prev=idx>0?steps[idx-1]:null;
  renderRegs(s,prev);renderFlags(s.flags);renderStack(s.stack);

  // Highlight active line in CFG
  highlightCFG(s.ip);

  // Note
  $('note-text').textContent=`[${idx+1}/${steps.length}] ${s.line}  →  ${s.note}`;
  $('note-text').style.color=
    s.note.includes('✓ TAKEN')?'var(--gr)':
    s.note.includes('✗ not taken')?'var(--rd)':'var(--yl)';

  $('sc').textContent=`${idx+1} / ${steps.length}`;
  $('bStep').disabled=idx>=steps.length-1;
  $('bBack').disabled=idx<=0;

  // Win check
  if(!winShown&&curMission){
    const wc=curMission.win_condition;
    if(wc.type==='reach_label'&&cfg){
      // Check if current ip matches the label
      const labelLine=cfg.label_map?.[wc.label];
      if(s.ip===labelLine){
        winShown=true;
        $('winTitle').textContent='Mission Complete!';
        $('winSubtitle').textContent='Good job. Here is your real flag:';
        $('winFlag').textContent=curMission.flag;
        setTimeout(()=>$('winOverlay').classList.add('show'),400);
        $('winIndicator').innerHTML='<span style="color:var(--gr);font-size:.65rem">✓ REACHED '+wc.label+'</span>';
      }
    }
  }
}

// ── CFG Rendering (div-based, SVG for edges) ──
let blockEls={};

function renderCFG(){
  if(!cfg||!cfg.blocks.length)return;
  const wrap=$('cfgWrap');
  wrap.innerHTML='';

  // Layout: simple top-down layered layout
  const layout=layoutCFG(cfg.blocks,cfg.edges);
  const W=layout.width+60,H=layout.height+60;

  // Container div for blocks
  const container=document.createElement('div');
  container.className='cfg-container';
  container.style.cssText=`position:relative;width:${W}px;height:${H}px`;

  // SVG overlay for edges
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('width',W);svg.setAttribute('height',H);
  svg.style.cssText='position:absolute;top:0;left:0;pointer-events:none';

  // Arrow marker defs
  const defs=document.createElementNS('http://www.w3.org/2000/svg','defs');
  ['gr','rd','mu'].forEach(c=>{
    const col=c==='gr'?'#a6e3a1':c==='rd'?'#f38ba8':'#6c7086';
    const mk=document.createElementNS('http://www.w3.org/2000/svg','marker');
    mk.setAttribute('id','arr-'+c);mk.setAttribute('viewBox','0 0 10 10');
    mk.setAttribute('refX','8');mk.setAttribute('refY','5');
    mk.setAttribute('markerWidth','5');mk.setAttribute('markerHeight','5');
    mk.setAttribute('orient','auto');
    const path=document.createElementNS('http://www.w3.org/2000/svg','path');
    path.setAttribute('d','M2 1L8 5L2 9');path.setAttribute('fill','none');
    path.setAttribute('stroke',col);path.setAttribute('stroke-width','1.5');
    path.setAttribute('stroke-linecap','round');
    mk.appendChild(path);defs.appendChild(mk);
  });
  svg.appendChild(defs);

  // Render blocks
  blockEls={};
  cfg.blocks.forEach(b=>{
    const pos=layout.positions[b.id];
    if(!pos)return;
    const el=document.createElement('div');
    el.className='cfg-block';
    el.id='block-'+b.id;
    el.style.left=pos.x+'px';el.style.top=pos.y+'px';
    el.style.width=pos.w+'px';

    // Header
    const hdr=document.createElement('div');
    hdr.className='cfg-block-header';
    const firstLabel=b.lines[0]?.label;
    hdr.innerHTML=`<span class="bid">${b.id}</span>`+(firstLabel?`<span class="blabel">${firstLabel}:</span>`:'');
    el.appendChild(hdr);

    // Lines
    b.lines.forEach(l=>{
      const ld=document.createElement('div');
      ld.className='cfg-line';ld.id=`cfgline-${l.idx}`;
      const parts=l.text.split(None=null,2);
      const mn=l.text.trim().split(/\s+/)[0]||'';
      const rest=l.text.trim().slice(mn.length).trim();
      const JUMPS=['jmp','je','jz','jne','jnz','jl','jg','jle','jge','ja','jb','call'];
      if(JUMPS.includes(mn.toLowerCase()))ld.classList.add('jump-line');
      if(mn.toLowerCase()==='ret')ld.classList.add('ret-line');
      // Split comment
      const ci=rest.indexOf(';');
      const ops=ci>=0?rest.slice(0,ci):rest;
      const cmt=ci>=0?rest.slice(ci):'';
      ld.innerHTML=`<span class="mnemonic">${esc(mn)}</span> <span class="operands">${esc(ops)}</span>`+(cmt?`<span class="comment"> ${esc(cmt)}</span>`:'');
      el.appendChild(ld);
    });

    container.appendChild(el);
    blockEls[b.id]=el;
  });

  // Render edges
  cfg.edges.forEach(e=>{
    const fromPos=layout.positions[e.from];
    const toPos=layout.positions[e.to];
    if(!fromPos||!toPos)return;
    const col=e.type==='true'||e.type==='jmp'?'#a6e3a1':e.type==='false'?'#f38ba8':'#4a4d58';
    const mk=e.type==='true'||e.type==='jmp'?'arr-gr':e.type==='false'?'arr-rd':'arr-mu';
    const dash=e.type==='false'?'4 3':'';

    // from bottom-center of source to top-center of target
    const x1=fromPos.x+fromPos.w/2;
    const y1=fromPos.y+fromPos.h;
    const x2=toPos.x+toPos.w/2;
    const y2=toPos.y;

    // Bezier curve
    const cy=Math.max(y1,y2);
    const path=document.createElementNS('http://www.w3.org/2000/svg','path');
    const d=`M${x1},${y1} C${x1},${y1+40} ${x2},${Math.max(y2-40,y1)} ${x2},${y2}`;
    path.setAttribute('d',d);
    path.setAttribute('fill','none');
    path.setAttribute('stroke',col);
    path.setAttribute('stroke-width','1.5');
    if(dash)path.setAttribute('stroke-dasharray',dash);
    path.setAttribute('marker-end',`url(#${mk})`);
    svg.appendChild(path);
  });

  container.appendChild(svg);
  wrap.appendChild(container);
}

function highlightCFG(ip){
  // Remove all active
  document.querySelectorAll('.cfg-line.active-line').forEach(el=>el.classList.remove('active-line'));
  document.querySelectorAll('.cfg-block.active-block').forEach(el=>el.classList.remove('active-block'));

  const lineEl=document.getElementById(`cfgline-${ip}`);
  if(lineEl){
    lineEl.classList.add('active-line');
    const block=lineEl.closest('.cfg-block');
    if(block){
      block.classList.add('active-block');
      // Scroll block into view in the CFG wrap
      block.scrollIntoView({block:'nearest',behavior:'smooth'});
    }
  }
}

// ── Simple layered CFG layout ──
function layoutCFG(blocks,edges){
  // BFS layer assignment from block B0
  const layers={};
  const queue=['B0'];
  layers['B0']=0;
  const visited=new Set(['B0']);
  // Build adjacency
  const adj={};
  blocks.forEach(b=>adj[b.id]=[]);
  edges.forEach(e=>{if(adj[e.from])adj[e.from].push(e.to);});

  while(queue.length){
    const cur=queue.shift();
    (adj[cur]||[]).forEach(next=>{
      if(!visited.has(next)){
        visited.add(next);
        layers[next]=(layers[cur]||0)+1;
        queue.push(next);
      }
    });
  }

  // Assign x positions within each layer
  const layerGroups={};
  blocks.forEach(b=>{
    const ly=layers[b.id]??0;
    if(!layerGroups[ly])layerGroups[ly]=[];
    layerGroups[ly].push(b.id);
  });

  const BW=220,BH_BASE=36,LINE_H=20,GAP_X=40,GAP_Y=70;
  const positions={};
  let maxX=0,maxY=0;

  Object.entries(layerGroups).forEach(([ly,bids])=>{
    const y=parseInt(ly)*(BH_BASE+GAP_Y)+30;
    const totalW=bids.length*(BW+GAP_X)-GAP_X;
    bids.forEach((bid,xi)=>{
      const block=blocks.find(b=>b.id===bid);
      const h=BH_BASE+block.lines.length*LINE_H;
      const x=xi*(BW+GAP_X)+30;
      positions[bid]={x,y,w:BW,h};
      maxX=Math.max(maxX,x+BW);
      maxY=Math.max(maxY,y+h);
    });
  });

  return{positions,width:maxX,height:maxY};
}

// ── Register / Flag / Stack render ──
function renderRegs(s,prev){
  $('regGrid').innerHTML='';
  REGS.forEach(n=>{
    const c=document.createElement('div');c.className='rc';
    if(s.highlight?.includes(n))c.classList.add('hi');
    else if(prev&&prev.regs[n]!==s.regs[n])c.classList.add('ch');
    c.innerHTML=`<div class="rn">${n.toUpperCase()}</div><div class="rv">${s.regs[n]}</div>`;
    $('regGrid').appendChild(c);
  });
}

function renderFlags(f){
  $('flagsRow').innerHTML='';
  Object.entries(f).forEach(([n,v])=>{
    const el=document.createElement('div');
    el.className=`fl ${v?'fset':'funset'}`;
    el.innerHTML=`<div class="fl-name">${n}</div><div class="fl-val">${v}</div>`;
    el.title={ZF:'Zero Flag',SF:'Sign Flag',CF:'Carry Flag',OF:'Overflow Flag'}[n]||n;
    $('flagsRow').appendChild(el);
  });
}

function renderStack(st){
  if(!st.length){$('stackList').innerHTML='<div class="se-empty">empty</div>';return;}
  $('stackList').innerHTML='';
  [...st].reverse().forEach(e=>{
    const el=document.createElement('div');el.className='se';
    el.innerHTML=`<div class="sa">${e.addr}</div><div class="sv">${e.val}</div><div class="sl">${esc(e.label)}</div>`;
    $('stackList').appendChild(el);
  });
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

// ── Init ──
buildTabs();
loadMission(1);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    html = HTML.replace("__MISSIONS_JSON__", json.dumps(MISSIONS))
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/simulate", methods=["POST"])
def simulate_route():
    data = request.get_json()
    code = data.get("code", "")
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    try:
        return jsonify(simulate(code))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cfg", methods=["POST"])
def cfg_route():
    data = request.get_json()
    code = data.get("code", "")
    if not code.strip():
        return jsonify({"error": "No code"}), 400
    try:
        return jsonify(build_cfg(code))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/check_flag", methods=["POST"])
def check_flag_route():
    data = request.get_json() or {}
    mission_id = data.get("mission_id")
    answer = data.get("answer", "")
    mission = next((m for m in MISSIONS if m["id"] == mission_id), None)
    if not mission:
        return jsonify({"ok": False, "error": "Invalid mission"}), 400
    normalized = normalize_answer(answer)
    accepted = {
        normalize_answer(mission["answer"]),
        normalize_answer(mission["flag"]),
    }
    ok = normalized in accepted
    if not ok:
        return jsonify({"ok": False}), 200
    return jsonify({"ok": True, "flag": mission["flag"]}), 200


if __name__ == "__main__":
    print("[*] CTF Assembly Lab")
    print("[*] Visit: http://localhost:8888/")
    app.run(host="0.0.0.0", port=8888, debug=False)
