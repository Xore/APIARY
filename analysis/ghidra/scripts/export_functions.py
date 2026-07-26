# Ghidra headless script: export all non-thunk functions to JSON stdout
# Run via: analyzeHeadless ... -postScript export_functions.py
# Output is written to <project>/functions.json

from ghidra.program.model.symbol import SourceType
import json, os

output = []
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    if func.isThunk():
        continue
    output.append({
        'address':     str(func.getEntryPoint()),
        'name':        func.getName(),
        'signature':   str(func.getSignature()),
        'caller_count': len(list(func.getCallingFunctions(monitor))),
        'callee_count': len(list(func.getCalledFunctions(monitor))),
        'source':      str(func.getSymbol().getSource()),
        'size':        func.getBody().getNumAddresses(),
    })

out_path = os.path.join(
    str(currentProgram.getDomainFile().getParent().getPathname()),
    'functions.json'
)
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print('Exported {} functions to {}'.format(len(output), out_path))
