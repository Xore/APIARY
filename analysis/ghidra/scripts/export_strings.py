# Ghidra headless script: export all defined strings to JSON
from ghidra.program.util import DefinedDataIterator
import json, os

output = []
for data in DefinedDataIterator.definedStrings(currentProgram):
    s = str(data.getValue())
    if len(s) >= 4:
        output.append({
            'address': str(data.getAddress()),
            'value':   s,
            'length':  len(s),
        })

out_path = os.path.join(
    str(currentProgram.getDomainFile().getParent().getPathname()),
    'strings.json'
)
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print('Exported {} strings'.format(len(output)))
