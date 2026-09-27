// #3326: mutation testing on the two pure modules, as a pilot.
//
// The question a pilot has to answer is "would a test notice if this code were
// wrong", and line coverage cannot answer it -- every line of these modules
// executing says nothing about whether an assertion reads the result. Stryker
// answers it the blunt way: change something, see whether anything fails.
//
// Deliberately not a gate. The issue asks for a *decision* on a ratchet from
// these numbers, and a number that is already failing CI stops being a
// measurement and starts being a wall. There is no `thresholds` block here and
// nothing in CI reads the score: the nightly records it and a human reads it.
//
// The mutate list is the whole of the pilot's scope and it is meant to stay
// short. These are the two modules whose behaviour is mostly a value in and a
// value out, so a mutant in them either is caught or describes a real gap.
// Widening it to the DOM- and network-touching modules would multiply the
// mutant count without multiplying what a survivor tells you, and Stryker's
// cost is per mutant.
export default {
  $schema: './node_modules/@stryker-mutator/core/schema/stryker-schema.json',
  packageManager: 'npm',
  // Two files: the cookie parse/serialise pair the property tests cover, and
  // the applier whose applyTheme ordering the DOM tests cover.
  //
  // prefs.ts is here even though it is not pure -- it is the issue's own
  // example, and "is the example in the issue a good one" is a result the pilot
  // is allowed to produce. See docs/frontend-mutation-pilot.md for what came of
  // it.
  mutate: ['src/lib/appearanceCookie.ts', 'src/lib/prefs.ts'],
  testRunner: 'vitest',
  // perTest runs only the files that import the mutant, which is the whole
  // reason this is affordable at all: the alternative re-runs all 23 test files
  // once per mutant.
  coverageAnalysis: 'perTest',
  // Excluding tsconfig.json from the sandbox, and that is a workaround rather
  // than a preference. Read with the note at the bottom of this file.
  ignorePatterns: ['/tsconfig.json'],
  reporters: ['clear-text', 'progress', 'html', 'json'],
  // No fileName overrides: the defaults are already reports/mutation/... and
  // setting them to a bare name puts the report in the package root, which is
  // both outside the .gitignore entry below and outside the path the nightly
  // uploads.
  // `string` is the mutator that earns its place here -- this is a parser, so
  // the interesting mutants are the ones that change a literal it compares
  // against. The default set also includes `objectLiteral` and `class`, which
  // have nothing to bite on in two files with neither.
  mutator: {
    plugins: [
      'arithmetic',
      'assignment',
      'boolean',
      'conditional',
      'equality',
      'logicalOperator',
      'optionalChaining',
      'string',
      'unary',
    ],
  },
  // Kept generous because the first mutants in these files sit in the
  // module-scope createServerFn() wiring, where a single vitest boot is the
  // unit of work. Raise this rather than let a mutant be recorded as a timeout
  // -- a timeout is not a measurement, it is the absence of one.
  timeoutMS: 20000,
  timeoutFactor: 2,
  concurrency: 2,
}

// Why tsconfig.json is ignored, since it looks arbitrary and is not:
//
// Stryker copies the project into a sandbox and rewrites the tsconfig there so
// that any `extends` or `references` path still resolves. That rewrite calls
// `ts.parseConfigFileTextToJson` from the installed typescript. This repo pins
// typescript ^7.0.2, the native (Go) compiler, whose entry point exports
// `version` and `versionMajorMinor` and nothing else -- the whole TypeScript
// 5 compiler API Stryker reaches for is gone. Stryker 10.0.0 fails before the
// first mutant runs:
//
//     TypeError: ts.parseConfigFileTextToJson is not a function
//         at TSConfigPreprocessor.rewriteTSConfigFile
//
// (Reproduced on node 22.23.2, the version the image ships. `tsconfigFile: null`
// is the other door out and Stryker's own schema validator rejects it: "Config
// option tsconfigFile has the wrong type. It should be a string, but was a
// null.")
//
// Ignoring the file is safe *for this project specifically*, and the reason is
// checked rather than assumed: this tsconfig has no `extends` and no
// `references`, so the rewrite Stryker wants to perform is a no-op here -- it
// would parse the file, find nothing to repoint, and write it back unchanged.
// The property that actually matters is that the sandbox's vitest run still
// behaves the same without it, and that is verifiable: `tsconfig.json` carries
// `paths` for `#/*` and `@/*`, and `grep -rl "from '#/\|from '@/" src/` returns
// zero files, so no source file resolves through them. There are no .test.tsx
// files, so the `jsx` setting has nothing to apply to. Running the full suite
// with tsconfig.json moved aside gives the same 205/205 as with it present.
//
// If Stryker gains TypeScript 7 support, delete this line and the workaround
// with it. If a future file starts importing through `#/*`, this line is what
// needs revisiting first.
