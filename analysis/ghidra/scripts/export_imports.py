# Ghidra headless script: export the import table (external function
# references) to JSON
# Run via: analyzeHeadless ... -postScript export_imports.py
# Output is written to <project>/imports.json

import json, os

output = []
fm = currentProgram.getFunctionManager()
for func in fm.getExternalFunctions():
    namespace = func.getParentNamespace()
    output.append({
        'address': str(func.getEntryPoint()),
        'name':    func.getName(),
        'library': namespace.getName() if namespace is not None else '',
    })

out_path = os.path.join(
    str(currentProgram.getDomainFile().getParent().getPathname()),
    'imports.json'
)
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print('Exported {} imports to {}'.format(len(output), out_path))
