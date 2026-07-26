# Ghidra headless script: export call graph in DOT format
# Top 200 functions by body size to keep graph manageable

import os

fm   = currentProgram.getFunctionManager()
funcs = sorted(
    [f for f in fm.getFunctions(True) if not f.isThunk()],
    key=lambda f: -f.getBody().getNumAddresses()
)[:200]

func_set = {str(f.getEntryPoint()) for f in funcs}
lines = ['digraph callgraph {']
lines.append('  rankdir=LR;')
lines.append('  node [shape=box fontsize=9];')

for func in funcs:
    src = str(func.getEntryPoint())
    label = func.getName()[:40].replace('"', "'")
    lines.append('  "{}" [label="{}"];'.format(src, label))
    for callee in func.getCalledFunctions(monitor):
        dst = str(callee.getEntryPoint())
        if dst in func_set:
            lines.append('  "{}" -> "{}";'.format(src, dst))

lines.append('}')

out_path = os.path.join(
    str(currentProgram.getDomainFile().getParent().getPathname()),
    'callgraph.dot'
)
with open(out_path, 'w') as f:
    f.write('\n'.join(lines))
print('Call graph exported: {} nodes'.format(len(funcs)))
