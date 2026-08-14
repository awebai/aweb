# Column B recorded-registry-state fixtures

Authored for R6 so that round assembles evidence instead of authoring it. These
are test data only: nothing here imports, or is imported by, any module. R6
wires them up.

The normative authority is `docs/aben-design.md` section 9. Where this directory
and that document disagree, the document wins and these files are wrong.

## What each file is

| file | row | consumer | shape |
| --- | --- | --- | --- |
| `b1-narrow-card.json` | B1 | normalizer | CapturedWorld registry half |
| `b2-stale-cli-version.json` | B2 | normalizer | CapturedWorld registry half |
| `b2-stale-cli-version.control-unpublished.json` | B2 control | normalizer | CapturedWorld registry half |
| `b3-single-floor-derivation.json` | B3 | normalizer | CapturedWorld registry half |
| `b4-impossible-pre-registered-shape.json` | B4 | normalizer | CapturedWorld registry half |
| `b4-impossible-pre-registered-shape.control-lagging-absent.json` | B4 control 1 | normalizer | CapturedWorld registry half |
| `b4-impossible-pre-registered-shape.control-lagging-conflicting.json` | B4 control 2 | normalizer | CapturedWorld registry half |
| `b5-false-publication-status.json` | B5 | R5 status engine | read-back observations |
| `normalizer-drift.json` | drift stop | normalizer | CapturedWorld registry half, snapshot pair |

Two shapes, deliberately. B5's consumer is R5's read-back status engine, not the
normalizer, and release-dev committed in advance to consuming exactly the shape
B5 is written in so that no translation layer gets built between these fixtures
and the code that reads them.

## The registry half only

Per R3's fixed consumer shape, `CapturedArtifact` carries repository facts
(`manifest_version`, `content_changed`, `derivation`) alongside registry
observations (`members`, `anchor_versions`). **Only the registry half is
authored here.** The repository half is captured by the normalizer at the pinned
SHAs, which is why several rows record a `repository_state` for context but
never a `content_changed` value.

This matters for B1 in particular: both of its controls vary `content_changed`,
not occupancy. Encoding them by editing occupancy would exercise a different
mechanism and still look green.

## `null` in `occupied` is load-bearing

`occupied` maps version to observable source identity, or `null` where the
member kind exposes none — pypi and npm listings. That `null` drives the
provisional-by-occupancy recoverability path, decided authoritatively by the
staged-byte comparison at publication.

So `null` means **"this registry kind exposes no identity"**. It must never mean
**"I could not observe the identity"**. Where a member kind does expose an
identity and this pass could not read it — every GHCR row, because those
manifest reads need a registry token — the value is written with method
`DERIVED-NOT-OBSERVED` and a warning naming what it was derived from. Collapsing
those to `null` would silently convert an unread identity into the identityless
case and change the semantics under test.

## Every value is marked re-observed or record-sourced, individually

The distinction is per value, not per file, because a file that mixes both and
says so only at the top invites the reader to generalise from whichever half
they checked.

Re-observed in this pass (2026-08-14, by aben-dev2), from the tags themselves
rather than from any record:

```
awid-service-v0.5.15  41008e6cb236c473546e84bd46660a9c852b264a
awid-v0.5.15          41008e6cb236c473546e84bd46660a9c852b264a
server-v1.27.1        6801b7c88339b45acfe6569de30c45732d43ba92
a2a-gw-v1.27.2        e5524b4b68828154446300ea9a79a5adce8a666f
aw-v1.34.5            2455e7a127ab5f216477a0af114cb69e5b0caa74
server-v1.27.2        ABSENT
```

Two of those are worth naming. `aw-v1.34.5` at `2455e7a1...` is exactly what the
design states from the cycle record — re-derived here from the tag, so the
fixture and the design agree by independent measurement rather than by
transcription, which is the one value where a copying error would have been
invisible. And `server-v1.27.2` not existing is independent corroboration of
B5's `pypi:aweb 1.27.2 ABSENT`, reached by a different route than the registry
inventory that recorded it.

Not re-observed, and therefore the values to trust least: **every GHCR row**
(token required) and the external `awebai/aw` Release object (not queried). Each
is marked at its own value.

## B5 is historical and re-observing it will contradict it

`pypi:awid-service 0.5.16` was **absent** at the moment B5 reconstructs
(2026-08-13 ~21:30Z) and is **present** today — the release completed after the
stop. That divergence is the fixture working, not the fixture rotting.

Anyone who "corrects" B5 against today's registries deletes its subject: with
awid-service present there is no false-status scenario left, and the row would
pass while proving nothing. The warning lives inside `b5-false-publication-status.json`
as well as here, because whoever is about to make that edit is reading the JSON,
not this file.

## Constructed fixtures are labelled as constructed

Three files describe worlds that never existed, because the property under test
is a fork the real cycle only ever took one branch of:

- `b2-...control-unpublished.json` — 1.34.5 unpublished (it is published)
- `b4-...control-lagging-absent.json` — the phantom-release direction whose
  occupancy is the *inverse* of what really happened
- `b4-...control-lagging-conflicting.json` — a conflicting source identity, using
  a deliberately synthetic 40-hex string that must not resolve to any commit

Each carries `"method": "CONSTRUCTED, not observed"` and a warning against
citing it as recorded state. The synthetic SHA in particular must not be
"fixed" into a real commit: a real one could coincide with the intended identity
and silently turn the conflicting control into the recoverable case, which is
the single distinction it exists to make.

## What the controls are for

Every control differs from its primary in exactly one respect and must produce a
different answer. That is what makes the primary's green mean something: a
resolver that ignores its input, or returns a constant, passes the primary alone
and fails the pair. Where a design-named control could not be expressed as data
— B3's two derive-script mutations, B5's injected probe failure, and the drift
stop's double-compute half — the file says so explicitly and names the mechanism
instead of quietly omitting it.

## Known gaps, stated rather than left to be discovered

- GHCR identities are derived, not observed. R6 should re-observe them with a
  token, or accept them as intended-values with that limitation recorded.
- The `aw-cli` cross-repository binding (peel both tags, compare the external
  tree excluding `.github` against the `cli/go` subtree via the sync workflow's
  own `ls-files -s` transform) was not executed. B2 records the aweb-side tag
  only.
- These fixtures have no consumer yet, so nothing currently proves they parse
  into `CapturedWorld` or that their expectations are the ones R6 asserts. They
  are authored against R3's shape as of `c1f54b21`; if that shape moves before
  R6, these move with it.
