---
name: sigmatcher-signature
description: >-
  Craft YAML signature files to identify obfuscated Java/Smali classes, methods,
  fields, and exports across multiple Android APK versions using sigmatcher.
license: MIT
---

Use this skill when you need to create or modify a `.sigma.yaml` signature file.
Start by reading the existing `AGENTS.md` and `README.md` for project context,
then generate the JSON schema with `sigmatcher schema --output definitions.schema.json`
and reference it from the sigfile with:

```yaml
# $schema: ./definitions.schema.json
# yaml-language-server: $schema=./definitions.schema.json
```

## Phase 1 — Decompile & cache

Decompilation only needs to happen once per APK. Check if the cache already
exists for each APK version:

```bash
ls "$(sigmatcher cache dir <APK>)/apktool" 2>/dev/null
```

If no output, decompile using your working sigfile. If starting fresh, use
process substitution or a temp empty sigfile:

```bash
sigmatcher analyze --signatures <(echo '[]') <APK>
```

The cache contains `apktool/<name>/smali*` — the decompiled smali directories.

## Phase 2 — Find candidate classes

Search the class name (or related keywords) across all smali files.
Sort by match count — the file with the most matches is likely the class itself:

```bash
rg -cF 'TargetClass' <cachedir>/apktool/ | sort -t: -k2 -rn
```

Files with 1-2 matches are other classes that *reference* the target
(via cast strings, field types, etc.). These are useful for the export technique.

Read the class declaration (first line) and a sample of strings in the candidate:

```bash
head -1 <smali_file>
rg -F 'TargetClass' <smali_file> | head -20
```

Repeat for every APK version to find common patterns.

## Phase 3 — Choose signatures (ordered by reliability)

### String constants (most reliable)

The original class name often survives in internal string constants
(e.g. `"NetworkManager/openConnection/some context message"`).
These are the most stable cross-version anchor.

**Caveat — R8 inlining:** Optimizers like R8 may inline methods into caller
classes, moving string constants with them. Always verify uniqueness globally:
`rg -cF 'NetworkManager' <cachedir>/apktool/`. A string that appears
in 5+ files may not be safe.

Example:

```yaml
- name: "NetworkManager"
  package: "com.example"
  signatures:
    - signature: '^\s*const-string v\d+, "NetworkManager/openConnection/some context message"$'
      type: regex
    - signature: '^\s*const-string v\d+, "NetworkManager/openConnection/some other context"$'
      type: regex
```

Multiple signatures at the same level are AND — all must match the same file.
`count` defaults to `1` (exactly one match); omit it unless you need a range.

### Exports + macros (when the target has no unique strings)

When the target class is hard to match directly (pure data class, no unique
string constants), find a *referencing* class that has an easily-matchable
string AND a field/method reference containing the target's obfuscated name.

Define the helper, capture the obfuscated name with an export, then bridge
to the target via macro:

```yaml
- name: "HelperWithRef"
  exports:
    - name: "targetRef"
      signatures:
        - signature: '^\.field public static final A:L(?P<match>X/\w+);$'
          type: regex
  signatures:
    - signature: '^\s*const-string v\d+, "null cannot be cast to non-null type com\.example\.NetworkManager"$'
      type: regex

- name: "NetworkManager"
  package: "com.example"
  signatures:
    - signature: '^\.class public L${HelperWithRef.exports.targetRef.value};$'
      type: regex
```

Key mechanics:

- `ExportDefinition` is a child of `ClassDefinition` — it scans the *parent's* smali file
- Exactly one regex signature per export (`TooManySignaturesError` otherwise)
- Named capture group `(?P<match>...)` defines the export value
- The dependency resolver ensures `HelperWithRef` runs first
- Accessible as `${<name>.exports.<name>.value}` in any signature macro
- Use `exclude: true` on helper definitions you don't want in final output

Methods on the referencing class are also useful:

```yaml
- name: "ConnectionHelper"
  methods:
    - name: "openConnection"
      signatures:
        - signature: '^\s*invoke-static.*${NetworkManager.java}->openConnection$'
          type: regex
```

### Methods / fields / interfaces (least stable)

Method/field/interface signatures tend to change between versions (ProGuard
renames them, R8 merges/rewrites). Use them only when string and export
approaches are exhausted.

## Phase 4 — Order signatures for performance

The analyzer processes signatures sequentially, intersecting results after each
one. The order matters:

1. **Most restrictive first** — the signature that filters out the most files
   should come first, shrinking the candidate set fastest. A specific
   `const-string` regex is more selective than a broad one.
2. **Blacklists last** — signatures with `min_count: 0` (`count: "0-1"`)
   should go last, after the candidate set is minimized.

The analyzer already promotes a whitelist signature (`min_count > 0`) to
position 0 automatically, but you should manually order the rest.

**Anchor with `^` / `$`:** Wrap patterns with `^` and `$` when they describe a
full line (most smali signatures do). This lets the regex engine skip mid-line
scans and reduces backtracking, especially for broad patterns. Use `^\s*` to
account for smali's 4-space instruction indentation:

```yaml
signatures:
  - signature: '^\s*const-string v\d+, "NetworkManager/openConnection/some context message"$'
    type: regex
```

Don't add anchors if the pattern is meant to match anywhere in a line.

## Phase 5 — Verify

Test against every APK version:

```bash
sigmatcher analyze --signatures sigs.yaml <APK>
```

Confirm exactly one class matches per APK. If a class fails to match, rerun
with `--debug` for detailed diagnostic output showing why each signature
failed:

```bash
sigmatcher analyze --signatures sigs.yaml --debug <APK>
```

Check that other classes with 1-2 references to the target name are NOT
matched (false positives). If they are, add stricter signatures or more of
them.

## Commands reference

```bash
# Schema for editor validation
sigmatcher schema --output definitions.schema.json

# Analyze (populate cache & test matching)
sigmatcher analyze --signatures sigs.yaml <APK>
sigmatcher analyze --signatures sigs.yaml --debug <APK>
sigmatcher analyze --signatures sigs.yaml --output-format enigma <APK>

# Cache utilities
sigmatcher cache dir <APK>
sigmatcher cache clear <APK>

# Search smali (inside the cache dir)
rg -cF 'ClassName' <cachedir>/apktool/ | sort -t: -k2 -rn
rg -F 'ClassName' <cachedir>/apktool/
```

## Checklist

- [ ] Ensure cache exists for all APK versions (`sigmatcher cache dir <APK>`)
- [ ] Find candidate files with `rg -cF` — identify target vs referencers
- [ ] Compare strings across versions — pick stable, unique signatures
- [ ] Verify uniqueness globally (`rg -cF` across all smali)
- [ ] Sort signatures by selectivity in the YAML
- [ ] Test against every APK version — exactly one match each
