// Canonical JSON value type — every raw Elasticsearch `_source` document
// (and any value derived from one: a `record` field, an `inventory`/
// `analysis` blob, a sandbox `Run`, …) is one of these at runtime, because
// it came from ES, which only ever returns JSON. `Record<string, unknown>`
// used to stand in for "ES document" everywhere, but TanStack Start's
// `createServerFn(...).handler(...)` return type is checked against
// `ValidateSerializableMapped<T, TSerializable>`
// (`@tanstack/router-core/src/ssr/serializer/transformer.ts`), which walks
// every property type looking for a proof that it's JSON-safe — an index
// signature with `unknown` values can't be proven safe (it could in theory
// hold a function or class instance), even though no real value here ever
// does. `Json` gives the checker an actual proof instead of `unknown`.
export type Json = string | number | boolean | null | Json[] | { [key: string]: Json }

// The shape of one row/document fetched from an ES-backed `/api/v1/store/*`
// endpoint (or similar). Alias kept distinct from `Json` itself so call
// sites read naturally: a store row is always an object, not any JSON value.
export type JsonRecord = Record<string, Json>
