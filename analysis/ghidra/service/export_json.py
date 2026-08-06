#@category Export
#@menupath Tools.Export JSON

# Independent post-script for the replacement Ghidra headless service (#245).
# Written from scratch against Ghidra's own public scripting API docs, not
# copied from the third-party biniamfd/ghidra-headless-rest image this
# replaces (that image's own export script carries no license, so it
# couldn't be reused verbatim even if the shape were identical).
#
# Deliberately narrow: analysis/ghidra/worker/ghidra-worker.py's GhidraClient
# only ever reads functions.json, strings.json, and imports.json (confirmed
# directly against its own docstring and _request call sites) -- no
# decompile/xrefs export here, unlike the third-party image's superset.
# Jython (Ghidra's default script interpreter for a plain .py file, no
# PyGhidra bridge configured) -- Python 2.7 syntax throughout.

import json
import os

from java.io import File

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

# --- strings.json -------------------------------------------------------
# DefinedDataIterator (via listing.getDefinedData) walks every data item
# Ghidra's analysis already classified; filtering to string-shaped types
# here avoids a second raw-memory scan the analyzer already made redundant.
strings = []
data_iter = listing.getDefinedData(True)
while data_iter.hasNext():
    data = data_iter.next()
    dtype_name = data.getDataType().getName().lower()
    if "string" not in dtype_name and "unicode" not in dtype_name:
        continue
    try:
        value = data.getDefaultValueRepresentation()
    except Exception:
        continue
    strings.append({"addr": addr_str(data.getAddress()), "s": value})
write_json("strings.json", {"count": len(strings), "strings": strings})

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

print("[export_json] wrote %d functions, %d strings, %d imports" % (
    len(functions), len(strings), len(imports)))
