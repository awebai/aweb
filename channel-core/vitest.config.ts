import { defaultExclude, defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // test/zz_probe_*.test.ts.recovered are reproductions for open defects, not tests.
    // Two of them assert the CURRENT, VULNERABLE behaviour, so collecting them would make
    // this suite assert that the defect exists - and fixing the defect would turn it red.
    // See server/tests/RECOVERED-PROBES.md for the full set and what landing each requires.
    //
    // Their suffix already keeps them out, but only as a side effect: vitest's default
    // include admits a name ending in .test.ts, and .recovered names do not end that way.
    // That makes the real guard the ABSENCE of a config file, which is the weakest kind -
    // nothing on disk says the probes must stay out, so dropping a suffix reads as a
    // rename rather than as putting a reproduction into the suite.
    //
    // So this matches them by NAME, not by suffix. A suffix-keyed pattern like
    // '**/*.recovered' could never fire: exclude only removes what include ADMITTED, and
    // a .recovered name is never admitted - while a name with the suffix dropped no longer
    // matches '.recovered' either. '**/zz_probe_*' holds in both states.
    //
    // defaultExclude is spread rather than replaced: an explicit exclude REPLACES the
    // defaults, so a bare list drops **/node_modules/** and any test-shaped file under a
    // dependency is collected. Nothing installed here matches the include today, so the
    // spread has no effect on the current list - it is what keeps that true when a future
    // dependency does ship one.
    //
    // include is deliberately not set. The default already collects every real test here,
    // and restating it would only create something to drift.
    exclude: [...defaultExclude, '**/zz_probe_*'],
  },
})
