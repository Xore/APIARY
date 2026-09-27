// composable-templates.js -- run by arkime-init right after db.pl (#3343).
//
// Arkime's db.pl installs LEGACY index templates (arkime_sessions3_template,
// arkime_sessions3_ecs_template, arkime_history_v1_template). Elasticsearch
// applies no legacy template to an index once any composable template matches
// it, and this cluster always has one: elasticsearch-setup.sh's
// single-node-replica-default matches "*" (composable templates have no
// exclusion syntax, so its "-arkime_..." entries are literal names). Every
// arkime_sessions3-* index was therefore created from dynamic defaults --
// firstPacket as long instead of date, node/tags as text, no wordSplit
// analyzer, no dynamic templates.
//
// This translates Arkime's live legacy templates into one composable template
// per index family, merged the way Elasticsearch merges legacy templates
// (ascending order, later wins; dynamic_templates by name), plus the three
// things this cluster needs on top: number_of_replicas 0 (single node, #3283),
// ip-typed source.ip/destination.ip (the viewer's fixSessionFields crashes on
// text IPs, #1191), and delete-only retention on the sessions family (#3283).
// Regenerated on every arkime-init run, so it follows whatever templates the
// running Arkime version's db.pl installed.
//
// #3283 retention, and why it lives here rather than in
// elasticsearch-setup.sh next to the other twelve policies:
//
//   * It was missing. Every daily index family in this stack is ILM-managed
//     except arkime_sessions3-*, which grew one index a day forever. #3362
//     removed the dominant term (Zeek's 84 per-day families became 84 per
//     month) and this was the last unbounded one left, so the shard
//     arithmetic still had a term that only ever adds. That is one more way
//     the single node reaches cluster.max_shards_per_node's 1000 default and
//     dead-letters all sensor ingest, as it did on 2026-09-21.
//   * The policy has to exist BEFORE the template that names it, and this
//     script is the only thing that installs that template. Elasticsearch
//     validates index.lifecycle.name at index creation, so a template
//     naming a policy that is not there yet fails the creation outright --
//     and arkime-init and elasticsearch-setup are independent one-shots that
//     race (elasticsearch-setup.sh waits for db.pl's legacy template because
//     of the mirror-image problem). A policy created in elasticsearch-setup
//     could not be relied on to exist before arkime-capture creates an
//     index, and arkime-capture waits only on arkime-init.done, not on
//     elasticsearch-setup.done. Creating the policy here, immediately before
//     the template that references it, is the ordering that cannot lose.
//   * The age is HONEYPOT_RETENTION_DAYS, the same single knob every other
//     window in this stack scales from (#261), passed into this container by
//     honeypot-init/compose.yml. Same window as the raw event stream rather
//     than suricata-7d's 7/30 share: the Arkime viewer and the Kibana "Arkime
//     Sessions" data view (docs/OPERATIONS.md) are supported workflows, and
//     21 shards is not the problem -- unbounded growth was.
//
// A composable template only governs indices created AFTER it is installed,
// so the run also adopts the arkime_sessions3-* indices already on disk.
// Adoption never overwrites an index that carries some other lifecycle name:
// that is an operator's deliberate choice, and this one-shot init job's log
// is the only place a warning about it can surface.
//
// DRY_RUN=1 prints the policy, the generated templates and the adoption
// plan, and changes nothing.
//
// Node 22 (shipped in the Arkime image), no dependencies. Exits non-zero on
// any failure so arkime-init's `set -e` never writes its done-marker over a
// half-applied state.
'use strict';

const ES = (process.env.ARKIME__elasticsearch || 'http://elasticsearch:9200').replace(/\/+$/, '');
const PRIORITY = 11; // above the #1191 ip-fix template (10) it replaces, so there is no gap
const LEGACY_IP_FIX = 'arkime-sessions3-ip-fix';

// #3283: same knob, same 30-day default as elasticsearch-setup.sh's
// `retention_days="${HONEYPOT_RETENTION_DAYS:-30}"`. Junk falls back rather
// than throwing, matching what a missing variable does; a value the shell
// would have choked on stops the whole stack before either of us gets here.
const RETENTION_DAYS = (() => {
  const raw = (process.env.HONEYPOT_RETENTION_DAYS || '').trim();
  if (!raw) return 30;
  const days = Number(raw);
  return Number.isInteger(days) && days > 0 ? days : 30;
})();
// Policy names stay fixed identifiers whose suffix states the shape of the
// window, not the number it currently resolves to -- the same convention
// suricata-7d/dashboard-app-30d follow, for the same reason.
const SESSIONS_POLICY = 'arkime-sessions-30d';

const FAMILIES = [
  {
    name: 'arkime-sessions3',
    pattern: 'arkime_sessions3-*',
    legacy: ['arkime_sessions3_template', 'arkime_sessions3_ecs_template'],
    ipFix: true,
    // #3283: the retention that makes this family bounded.
    retention: SESSIONS_POLICY,
  },
  {
    name: 'arkime-history-v1',
    pattern: 'arkime_history_v1-*',
    legacy: ['arkime_history_v1_template'],
    ipFix: false,
    // No retention, deliberately. config.ini never sets `history=`, so
    // Arkime's default applies and this family is not created at all; it is
    // here only so the template is translated correctly if an operator turns
    // it on, and search history is a different data class from session
    // telemetry with its own retention question to answer (#3283).
    retention: null,
  },
];

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Recursive object merge; `over` wins on scalar and array conflicts.
function deepMerge(base, over) {
  if (!isObj(base) || !isObj(over)) return over === undefined ? base : over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = k in out ? deepMerge(out[k], v) : v;
  return out;
}

// dynamic_templates is a list of single-key {name: spec} objects, and
// Elasticsearch uses the FIRST entry that matches a field. A higher-order
// template must take precedence, so its entries go first and a same-named
// entry from a lower-order template is dropped. Getting this backwards puts
// arkime_sessions3_ecs_template's catch-all strings_as_keyword (order 1)
// ahead of Arkime's own *Ip / *Tokens rules (order 99), and every *Ip field
// lands as keyword -- verified on a throwaway index.
function mergeDynamicTemplates(listsAscending) {
  const seen = new Set();
  const out = [];
  for (const list of [...listsAscending].reverse()) {
    for (const entry of list || []) {
      const name = Object.keys(entry)[0];
      if (seen.has(name)) continue;
      seen.add(name);
      out.push(entry);
    }
  }
  return out;
}

async function es(method, path, body) {
  const res = await fetch(ES + path, {
    method,
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : {} };
}

function build(family, legacyTemplates) {
  const sorted = [...legacyTemplates].sort((a, b) => (a.order || 0) - (b.order || 0));
  let settings = {};
  let mappings = {};
  let aliases = {};
  const dyn = [];
  for (const t of sorted) {
    settings = deepMerge(settings, t.settings || {});
    const { dynamic_templates: d, ...rest } = t.mappings || {};
    mappings = deepMerge(mappings, rest);
    dyn.push(d);
    aliases = deepMerge(aliases, t.aliases || {});
  }
  // Cluster-local settings, applied last so they win over whatever the
  // legacy templates said. #3283: same reason number_of_replicas is here --
  // a composable template does not merge with a legacy one, it replaces it,
  // so anything this cluster needs has to be stated explicitly.
  const clusterSettings = { number_of_replicas: '0' };
  if (family.retention) clusterSettings['lifecycle.name'] = family.retention;
  settings = deepMerge(settings, { index: clusterSettings });
  const merged = mergeDynamicTemplates(dyn);
  if (merged.length) mappings.dynamic_templates = merged;
  if (family.ipFix) {
    mappings = deepMerge(mappings, {
      properties: {
        source: { properties: { ip: { type: 'ip' } } },
        destination: { properties: { ip: { type: 'ip' } } },
      },
    });
  }
  const added = family.retention
    ? ` Retained by ${family.retention}; replicas 0 for this single node (#3283).`
    : ' Replicas 0 for this single node (#3283).';
  return {
    index_patterns: [family.pattern],
    priority: PRIORITY,
    template: { settings, mappings, aliases },
    _meta: {
      description: `Generated by arkime-init from Arkime's legacy ${family.legacy.join(' + ')} (#3343).${added} Do not edit; re-run arkime-init.`,
      source: '#3343, #3283',
    },
  };
}

// #3283: delete-only, the same shape as every policy in
// elasticsearch-setup.sh's loop. `hot` has to be present and empty: a
// policy's phases are replaced wholesale, not merged, so omitting it drops
// the phase rather than defaulting it.
function policyBody(minAge) {
  return {
    policy: {
      phases: {
        hot: { actions: {} },
        delete: { min_age: minAge, actions: { delete: {} } },
      },
    },
  };
}

async function ensurePolicy(name, minAge) {
  const body = policyBody(minAge);
  if (process.env.DRY_RUN) {
    console.log(JSON.stringify({ [`_ilm/policy/${name}`]: body }));
    return;
  }
  // PUT is the create-or-replace verb, so this is idempotent across the
  // re-runs arkime-init does on every deploy.
  const put = await es('PUT', `/_ilm/policy/${name}`, body);
  if (put.status !== 200 && put.status !== 201) throw new Error(`PUT _ilm/policy/${name}: HTTP ${put.status} ${JSON.stringify(put.json)}`);
  console.log(`${name}: delete-only ILM policy installed, delete.min_age ${minAge}`);
}

// #3283: put the indices that predate this template under the same policy.
// A composable template only governs what is created after it exists, so
// without this the ~12 daily indices already on disk would stay unmanaged
// forever and the family would keep its current size while appearing fixed.
async function adoptExisting(pattern, policy) {
  // expand_wildcards=all so a closed index is adopted too, and h=index so
  // the reply is a bare list of names.
  const list = await es('GET', `/_cat/indices/${encodeURIComponent(pattern)}?format=json&h=index&expand_wildcards=all`);
  if (list.status !== 200) throw new Error(`GET _cat/indices/${pattern}: HTTP ${list.status} ${JSON.stringify(list.json)}`);
  const rows = Array.isArray(list.json) ? list.json : [];
  const names = rows.map((row) => row && row.index).filter((name) => typeof name === 'string');
  if (process.env.DRY_RUN) {
    console.log(`${policy}: would adopt ${names.length} existing ${pattern} index(es): ${names.join(' ') || '(none)'}`);
    return;
  }
  let adopted = 0;
  let kept = 0;
  for (const name of names) {
    const current = await es('GET', `/${encodeURIComponent(name)}/_settings?flat_settings=true`);
    if (current.status !== 200) throw new Error(`GET /${name}/_settings: HTTP ${current.status} ${JSON.stringify(current.json)}`);
    const existing = ((current.json || {})[name] || {}).settings?.['index.lifecycle.name'];
    if (existing === policy) {
      kept += 1;
      continue;
    }
    if (existing) {
      // Not an error and not something to overwrite: this is the one place
      // an operator-set lifecycle name on an Arkime index can be seen.
      console.log(`${name}: left alone, it already carries index.lifecycle.name=${existing} (this stack's policy is ${policy})`);
      continue;
    }
    const put = await es('PUT', `/${encodeURIComponent(name)}/_settings`, { 'index.lifecycle.name': policy });
    if (put.status !== 200) throw new Error(`PUT /${name}/_settings: HTTP ${put.status} ${JSON.stringify(put.json)}`);
    adopted += 1;
    console.log(`${name}: adopted ${policy}`);
  }
  console.log(`${pattern}: ${adopted} index(es) adopted, ${kept} already on ${policy}`);
}

async function main() {
  const managed = [];
  for (const family of FAMILIES) {
    const found = [];
    for (const name of family.legacy) {
      const r = await es('GET', `/_template/${name}`);
      if (r.status === 404) continue;
      if (r.status !== 200) throw new Error(`GET _template/${name}: HTTP ${r.status}`);
      found.push(r.json[name]);
    }
    if (!found.length) {
      console.log(`${family.name}: none of ${family.legacy.join(', ')} exist yet -- skipped`);
      continue;
    }
    managed.push(family);
    // #3283: before the template, never after. See the header comment.
    if (family.retention) await ensurePolicy(family.retention, `${RETENTION_DAYS}d`);
    const body = build(family, found);
    if (process.env.DRY_RUN) {
      console.log(JSON.stringify({ [family.name]: body }));
      continue;
    }
    const put = await es('PUT', `/_index_template/${family.name}`, body);
    if (put.status !== 200) throw new Error(`PUT _index_template/${family.name}: HTTP ${put.status} ${JSON.stringify(put.json)}`);
    // replaceAll, not replace: replace() substitutes only the first '*', so a
    // pattern carrying more than one wildcard would be only partly replaced and
    // the probe would POST against a real index name instead of the synthetic
    // one. Both current patterns hold a single '*', so behaviour is unchanged
    // today; replaceAll keeps it correct as the family table grows.
    const sim = await es('POST', `/_index_template/_simulate_index/${family.pattern.replaceAll('*', 'composable-check')}`);
    const replicas = sim.json?.template?.settings?.index?.number_of_replicas;
    if (replicas !== '0') throw new Error(`${family.name}: simulate shows number_of_replicas=${replicas}, expected 0`);
    if (family.retention) {
      // The #3283 half of the same check. A template whose retention never
      // made it into the composed settings would install cleanly and leave
      // every new index unmanaged -- the exact state this exists to end, and
      // invisible from here, so it is verified rather than assumed.
      const lifecycle = sim.json?.template?.settings?.index?.['lifecycle.name'];
      if (lifecycle !== family.retention) {
        throw new Error(`${family.name}: simulate shows index.lifecycle.name=${lifecycle}, expected ${family.retention}`);
      }
    }
    console.log(`${family.name}: composable template installed from ${found.length} legacy template(s), priority ${PRIORITY}`);
  }
  // #3283: retention reaches the indices that already exist. Before the
  // dead-template delete below, so a failure there cannot cost this -- and
  // before the DRY_RUN return, so a preview includes the adoption plan.
  for (const family of managed) {
    if (family.retention) await adoptExisting(family.pattern, family.retention);
  }
  if (process.env.DRY_RUN) return;
  const old = await es('DELETE', `/_index_template/${LEGACY_IP_FIX}`);
  if (old.status === 200) console.log(`${LEGACY_IP_FIX}: removed (superseded by arkime-sessions3)`);
  else if (old.status !== 404) throw new Error(`DELETE _index_template/${LEGACY_IP_FIX}: HTTP ${old.status}`);
}

main().catch((err) => {
  console.error(`composable-templates: ${err.message}`);
  process.exit(1);
});
