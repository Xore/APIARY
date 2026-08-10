#@category Export
#@menupath Tools.Export JSON

# Independent post-script for the replacement Ghidra headless service (#245).
# Written from scratch against Ghidra's own public scripting API docs, not
# copied from the third-party biniamfd/ghidra-headless-rest image this
# replaces (that image's own export script carries no license, so it
# couldn't be reused verbatim even if the shape were identical).
#
# analysis/ghidra/worker/ghidra-worker.py's GhidraClient only ever reads
# functions.json, strings.json, and imports.json (confirmed directly
# against its own docstring and _request call sites). decompiled.json and
# xrefs.json below are for #1164's locally-evaluated RevDeck rewrite --
# its chat tool-calling needs on-demand per-function decompilation and
# caller/callee xrefs, and this service never keeps a Ghidra project open
# between requests to answer that live, so it's precomputed here instead
# (server.py's /tools/decompile_function and /tools/get_xrefs just look up
# these files by address; no second analyzeHeadless invocation).
# Jython (Ghidra's default script interpreter for a plain .py file, no
# PyGhidra bridge configured) -- Python 2.7 syntax throughout.

import json
import os

import jarray
from java.io import File
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import Structure, Union, Enum, TypeDef
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs() or []
out_dir = args[0] if len(args) >= 1 else os.path.join(os.environ.get("HOME", "/tmp"), "ghidra_export")
if not os.path.isdir(out_dir):
    File(out_dir).mkdirs()


def write_json(name, value):
    path = os.path.join(out_dir, name)
    handle = open(path, "w")
    try:
        handle.write(json.dumps(value, indent=2, sort_keys=True))
    finally:
        handle.close()


def addr_str(address):
    return "0x%x" % address.getOffset()


prog = currentProgram
listing = prog.getListing()

# --- functions.json ---------------------------------------------------
functions = []
func_iter = listing.getFunctions(True)
while func_iter.hasNext():
    fn = func_iter.next()
    functions.append({
        "addr": addr_str(fn.getEntryPoint()),
        "name": fn.getName(),
        "canonical_name": fn.getName(True),
        "signature": fn.getSignature().getPrototypeString(False),
        "size": int(fn.getBody().getNumAddresses()),
    })
write_json("functions.json", {
    "total": len(functions),
    "offset": 0,
    "limit": len(functions),
    "functions": functions,
})

# --- xrefs.json + decompiled.json ---------------------------------------
# Xrefs are cheap (just the reference graph Ghidra's own analysis already
# built) and computed for every function. Decompilation is the expensive
# part, so it is bounded: only the first MAX_DECOMPILE_FUNCTIONS get real
# pseudocode, each capped at DECOMPILE_TIMEOUT_SECONDS, so one pathological
# function or an unusually large binary can't blow the whole job's own
# ANALYSIS_TIMEOUT. A function past the cap still has working xrefs; the
# analyst can decompile it by hand in the interactive Ghidra GUI if needed.
MAX_DECOMPILE_FUNCTIONS = int(os.environ.get("GHIDRA_MAX_DECOMPILE_FUNCTIONS", "500"))
DECOMPILE_TIMEOUT_SECONDS = int(os.environ.get("GHIDRA_DECOMPILE_TIMEOUT_SECONDS", "30"))

decompiler = DecompInterface()
decompiler.openProgram(prog)
xref_monitor = ConsoleTaskMonitor()

xrefs = {}
decompiled = {}
decompiled_count = 0
func_iter2 = listing.getFunctions(True)
while func_iter2.hasNext():
    fn = func_iter2.next()
    key = addr_str(fn.getEntryPoint())

    callers = []
    for caller in fn.getCallingFunctions(xref_monitor):
        callers.append({"addr": addr_str(caller.getEntryPoint()), "name": caller.getName()})
    callees = []
    for callee in fn.getCalledFunctions(xref_monitor):
        callees.append({"addr": addr_str(callee.getEntryPoint()), "name": callee.getName()})
    xrefs[key] = {"callers": callers, "callees": callees}

    if decompiled_count < MAX_DECOMPILE_FUNCTIONS:
        decompiled_count += 1
        try:
            results = decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECONDS, xref_monitor)
            if results.decompileCompleted():
                decompiled_func = results.getDecompiledFunction()
                decompiled[key] = {
                    "pseudocode": decompiled_func.getC(),
                    "signature": decompiled_func.getSignature(),
                }
            else:
                decompiled[key] = {"error": results.getErrorMessage() or "decompilation did not complete"}
        except Exception as exc:
            decompiled[key] = {"error": str(exc)}
decompiler.dispose()

write_json("xrefs.json", xrefs)
write_json("decompiled.json", {
    "decompiled_count": decompiled_count,
    "total_functions": len(functions),
    "truncated": decompiled_count < len(functions),
    "functions": decompiled,
})

# --- strings.json + globals.json -----------------------------------------
# DefinedDataIterator (via listing.getDefinedData) walks every data item
# Ghidra's analysis already classified; one pass splits string-shaped items
# (strings.json, matches worker/ghidra-worker.py's existing GhidraClient
# shape) from every other named data symbol (globals.json, #1164/main's
# fetch_globals -- no synthesis fallback client-side, so this has to be
# real). Unnamed/anonymous data is skipped for globals: it is not a symbol
# an analyst or the chat tool-calling loop could ask about by name.
MAX_GLOBALS = int(os.environ.get("GHIDRA_MAX_GLOBALS", "5000"))

strings = []
globals_list = []
data_iter = listing.getDefinedData(True)
while data_iter.hasNext():
    data = data_iter.next()
    dtype_name = data.getDataType().getName().lower()
    if "string" in dtype_name or "unicode" in dtype_name:
        try:
            value = data.getDefaultValueRepresentation()
        except Exception:
            continue
        strings.append({"addr": addr_str(data.getAddress()), "s": value})
        continue
    if len(globals_list) >= MAX_GLOBALS:
        continue
    sym = data.getPrimarySymbol()
    name = sym.getName() if sym is not None else None
    if not name:
        continue
    globals_list.append({
        "addr": addr_str(data.getAddress()),
        "name": name,
        "type": data.getDataType().getName(),
        "size": int(data.getLength()),
    })
write_json("strings.json", {"count": len(strings), "strings": strings})
write_json("globals.json", {
    "total": len(globals_list),
    "truncated": len(globals_list) >= MAX_GLOBALS,
    "globals": globals_list,
})

# --- types.json -----------------------------------------------------------
# Structures/unions/enums/typedefs from the program's own DataTypeManager --
# #1164/main's fetch_types has no synthesis fallback either. Built-in and
# library-supplied primitive types are filtered out by the isinstance
# checks below; only composite/enum/typedef types a user or the binary's
# own debug info actually defined are exported.
MAX_TYPES = int(os.environ.get("GHIDRA_MAX_TYPES", "5000"))

types = []
dtm = prog.getDataTypeManager()
dt_iter = dtm.getAllDataTypes()
while dt_iter.hasNext() and len(types) < MAX_TYPES:
    dt = dt_iter.next()
    try:
        if isinstance(dt, Structure) or isinstance(dt, Union):
            fields = []
            for component in dt.getComponents():
                field_dt = component.getDataType()
                fields.append({
                    "name": component.getFieldName() or ("field_0x%x" % component.getOffset()),
                    "type": field_dt.getName() if field_dt is not None else "undefined",
                    "offset": int(component.getOffset()),
                    "size": int(component.getLength()),
                })
            types.append({
                "name": dt.getName(),
                "kind": "union" if isinstance(dt, Union) else "struct",
                "size": int(dt.getLength()),
                "fields": fields,
            })
        elif isinstance(dt, Enum):
            values = {}
            for enum_name in dt.getNames():
                values[enum_name] = dt.getValue(enum_name)
            types.append({
                "name": dt.getName(),
                "kind": "enum",
                "size": int(dt.getLength()),
                "values": values,
            })
        elif isinstance(dt, TypeDef):
            base = dt.getBaseDataType()
            types.append({
                "name": dt.getName(),
                "kind": "typedef",
                "size": int(dt.getLength()),
                "base_type": base.getName() if base is not None else "undefined",
            })
    except Exception:
        continue  # one exotic/malformed type must not lose the rest
write_json("types.json", {
    "total": len(types),
    "truncated": len(types) >= MAX_TYPES,
    "types": types,
})

# --- imports.json ---------------------------------------------------------
# External functions (dynamic-linked imports) via the ExternalManager --
# the same source Ghidra's own Symbol Tree "External Programs" view reads.
imports = []
ext_mgr = prog.getExternalManager()
for lib_name in ext_mgr.getExternalLibraryNames():
    it = ext_mgr.getExternalLocations(lib_name)
    while it.hasNext():
        loc = it.next()
        label = loc.getLabel()
        if not label:
            continue
        entry = {"name": label, "library": lib_name}
        if loc.getAddress() is not None:
            entry["address"] = addr_str(loc.getAddress())
        imports.append(entry)
write_json("imports.json", imports)

# --- memory.bin + memory_map.json -----------------------------------------
# #1164/main's fetch_hexdump asks for an arbitrary bounded byte range at
# request time, long after this one-shot analyzeHeadless process has
# exited -- so the bytes have to already be on disk. Every initialized
# memory block gets concatenated into one flat file in address order;
# memory_map.json records where each block starts in that file, so
# server.py can translate a requested address straight to a (file_offset,
# length) read without re-opening the Ghidra project. Uninitialized blocks
# (BSS-like, no real byte content) are skipped. Bounded by
# GHIDRA_MAX_MEMORY_DUMP_BYTES so a huge or heavily-padded image can't
# blow the job's own disk/time budget -- a block that would cross the cap
# is skipped whole, not truncated mid-block, so every dumped block's bytes
# stay self-consistent.
MAX_MEMORY_DUMP_BYTES = int(os.environ.get("GHIDRA_MAX_MEMORY_DUMP_BYTES", str(64 * 1024 * 1024)))
MEMORY_CHUNK_BYTES = 1 << 20  # 1 MiB read/write chunks, bounded regardless of block size

memory = prog.getMemory()
memory_map = []
mem_out = open(os.path.join(out_dir, "memory.bin"), "wb")
file_offset = 0
try:
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        size = int(block.getSize())
        if file_offset + size > MAX_MEMORY_DUMP_BYTES:
            continue
        stream = block.getData()
        if stream is None:
            continue
        try:
            written = 0
            while written < size:
                want = min(MEMORY_CHUNK_BYTES, size - written)
                buf = jarray.zeros(want, "b")
                n = stream.read(buf, 0, want)
                if n <= 0:
                    break
                mem_out.write("".join(chr(b & 0xff) for b in buf[:n]))
                written += n
        finally:
            stream.close()
        memory_map.append({
            "name": block.getName(),
            "start": addr_str(block.getStart()),
            "end": addr_str(block.getEnd()),
            "file_offset": file_offset,
            "size": written,
        })
        file_offset += written
finally:
    mem_out.close()
write_json("memory_map.json", {"blocks": memory_map, "total_bytes": file_offset})

print("[export_json] wrote %d functions, %d strings, %d imports, %d globals, %d types, "
      "%d xrefs, %d/%d decompiled, %d memory block(s) (%d bytes)" % (
    len(functions), len(strings), len(imports), len(globals_list), len(types),
    len(xrefs), decompiled_count, len(functions), len(memory_map), file_offset))
