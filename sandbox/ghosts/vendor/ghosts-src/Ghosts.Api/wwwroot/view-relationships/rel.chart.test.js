// Regression test for the "chart" cell in rel.js.
//
// The Observable runtime only attaches DOM nodes returned by a cell to the
// page; a cell that evaluates to a string renders as inert text. This test
// drives the real "chart" cell function (extracted from rel.js without
// pulling in the browser or the Observable runtime) with a fake d3 and
// asserts the cell returns a renderable node, and that the per-NPC circle
// fill references a well-formed pattern id (the exact thing a stray
// `+ `)"`` outside `.attr()` used to corrupt).

import assert from "node:assert/strict";
import test from "node:test";
import define from "./rel.js";

class FakeElement {
    constructor(tag) {
        this.tagName = tag;
        this.attributes = {};
        this.styles = {};
        this.children = [];
        this.textContent = undefined;
    }
}

class FakeSelection {
    constructor(elements, parents) {
        this._elements = elements;
        this._parents = parents;
    }

    attr(name, value) {
        for (const el of this._elements) {
            el.attributes[name] = typeof value === "function" ? value(el.__datum__) : value;
        }
        return this;
    }

    style(name, value) {
        for (const el of this._elements) {
            el.styles[name] = typeof value === "function" ? value(el.__datum__) : value;
        }
        return this;
    }

    text(value) {
        for (const el of this._elements) {
            el.textContent = typeof value === "function" ? value(el.__datum__) : value;
        }
        return this;
    }

    append(tag) {
        const children = this._elements.map(el => {
            const child = new FakeElement(tag);
            child.__datum__ = el.__datum__;
            el.children.push(child);
            return child;
        });
        return new FakeSelection(children);
    }

    selectAll(_selector) {
        return new FakeSelection([], this._elements);
    }

    data(arr) {
        this._data = arr;
        return this;
    }

    join(tag) {
        const created = [];
        for (const parent of this._parents) {
            for (const d of this._data) {
                const el = new FakeElement(tag);
                el.__datum__ = d;
                parent.children.push(el);
                created.push(el);
            }
        }
        return new FakeSelection(created);
    }

    call(fn) {
        fn(this);
        return this;
    }

    clone(_deep) {
        return this;
    }

    lower() {
        return this;
    }

    node() {
        return this._elements[0];
    }
}

function makeFakeD3() {
    const chainable = (extra = {}) => {
        const obj = { ...extra };
        for (const key of ["id", "strength", "distance"]) {
            obj[key] = () => obj;
        }
        return obj;
    };

    return {
        create: tag => new FakeSelection([new FakeElement(tag)]),
        forceSimulation: () => ({
            force: () => ({ force: () => {}, on: () => {} }),
            on: () => {},
        }),
        forceLink: () => chainable(),
        forceManyBody: () => chainable(),
        forceX: () => ({}),
        forceY: () => ({}),
    };
}

function extractCell(name) {
    let mainDefs;
    const fakeRuntime = {
        module() {
            const defs = new Map();
            if (!mainDefs) mainDefs = defs;
            return {
                builtin() {},
                import() {},
                variable() {
                    return {
                        define(nameOrDeps, depsOrFn, maybeFn) {
                            let cellName = nameOrDeps;
                            let deps = depsOrFn;
                            let fn = maybeFn;
                            if (typeof cellName !== "string") {
                                fn = depsOrFn;
                                deps = nameOrDeps;
                                cellName = undefined;
                            }
                            if (cellName) defs.set(cellName, { deps, fn });
                        },
                    };
                },
                fileAttachments: () => () => {},
            };
        },
        fileAttachments: () => () => {},
    };

    define(fakeRuntime, () => undefined);
    const cell = mainDefs.get(name);
    assert.ok(cell, `expected a "${name}" cell to be registered`);
    return cell;
}

test("chart cell returns a renderable svg node, not a stringified selection", () => {
    const cell = extractCell("chart");

    const npcId = "11111111-1111-1111-1111-111111111111";
    const links = [{ source: "alice", target: "bob", type: "friend", npc_id: npcId }];
    const nodeIds = Array.from(new Set(links.flatMap(l => [l.source, l.target])), id => ({ id }));
    const data = { nodes: nodeIds, links };

    const deps = {
        data,
        d3: makeFakeD3(),
        width: 800,
        height: 600,
        types: ["friend"],
        color: () => "steelblue",
        location: "http://localhost/view-relationships/",
        drag: () => selection => selection,
        linkArc: () => "",
        invalidation: new Promise(() => {}),
    };

    const result = cell.fn(...cell.deps.map(name => deps[name]));

    assert.notEqual(typeof result, "string", "chart cell must not return a stringified selection");
    assert.ok(result && typeof result === "object", "chart cell must return a node");
    assert.equal(result.tagName, "svg");

    const fills = [];
    (function collectCircleFills(el) {
        if (el.tagName === "circle" && "fill" in el.attributes) fills.push(el.attributes.fill);
        for (const child of el.children) collectCircleFills(child);
    })(result);

    assert.ok(fills.length > 0, "expected at least one NPC circle to be rendered");
    for (const fill of fills) {
        assert.match(fill, /^url\(#d[^)]*\)$/, `circle fill "${fill}" must be a well-formed pattern reference`);
    }
});
