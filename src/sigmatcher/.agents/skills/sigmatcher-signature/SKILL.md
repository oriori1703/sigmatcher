---
name: sigmatcher-signature
description: >-
  Create and debug sigmatcher YAML signatures to identify
  ProGuard/R8-obfuscated Java/Smali classes across Android APK
  versions. Use when building signature files, matching obfuscated
  classes by string constants, using regex/export/macro techniques,
  or verifying sigfiles against multiple APK version pairs.
license: MIT
compatibility: Requires Python 3.10+, uv, ripgrep (rg), and apktool
---

Use this skill when you need to create or modify a `.sigma.yaml` signature file.
See `references/SIGFILE_REFERENCE.md` for the signature format spec and
`references/MACROS.md` for the macro property reference.

Generate the JSON schema and reference it from the sigfile for editor validation:

```bash
sigmatcher schema --output definitions.schema.json
```

```yaml
# $schema: ./definitions.schema.json
# yaml-language-server: $schema=./definitions.schema.json
```

## Gotchas

Things that are easy to get wrong if you don't know them:

- **R8 inlining moves strings.** A string constant in class A may appear in
  class B's smali if B inlined A's method. Always verify uniqueness globally
  with `rg -cF` — a string appearing in 5+ files may not be safe.
- **`count: 1` is the default.** Omit it unless you need a different range.
- **`${Class.java}` includes `L` and `;`.** The `.java` property returns
  `Lcom/example/Class;` — don't add extra `L`/`;` around the macro.
- **Package can change between versions.** The `package` field is output
  labeling, not a match filter.
- **`sigmatcher cache dir` always returns a path.** It doesn't error if the
  cache doesn't exist. Check for `apktool/` inside.
- **Multiple signatures at the same level are AND.** Every signature must
  match the same file for the definition to match.

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

Search the class name (or related keywords) across all smali files and sort by
match count — the file with the most matches is likely the class itself:

```bash
rg -cF 'TargetClass' $(sigmatcher cache dir <APK>)/apktool/ | sort -t: -k2 -rn
```

Files with 1-2 matches are other classes that *reference* the target
(via cast strings, field types, etc.). These are useful for the export
technique. Read the class declaration and inspect the strings:

```bash
head -1 <smali_file>
rg -F 'TargetClass' <smali_file>
```

Repeat for every APK version — a good signature must match across all of them.

## Phase 3 — Choose signatures (ordered by reliability)

### String constants (most reliable)

The original class name often survives in internal string constants
(e.g. `"NetworkManager/openConnection/some context message"`). These are the
most stable cross-version anchor:

```yaml
- name: "NetworkManager"
  package: "com.example"
  signatures:
    - signature: '^\s*const-string v\d+, "NetworkManager/openConnection/some context message"$'
      type: regex
    - signature: '^\s*const-string v\d+, "NetworkManager/openConnection/some other context"$'
      type: regex
```

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

Key mechanics: export definitions scan the *parent's* smali file, use exactly
one regex signature with `(?P<match>...)`, and are accessible as
`${<name>.exports.<name>.value}`. Use `exclude: true` on helpers you don't
want in final output. See `references/MACROS.md` for the full property table.

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
scans and reduces backtracking. Use `^\s*` to account for smali's 4-space
instruction indentation:

```yaml
signatures:
  - signature: '^\s*const-string v\d+, "NetworkManager/openConnection/some context message"$'
    type: regex
```

Don't add anchors if the pattern is meant to match anywhere in a line.

## Phase 5 — Verify and iterate

Test against every APK version. If verification fails, inspect the debug
output, adjust, and re-test:

```bash
sigmatcher analyze --signatures sigs.yaml <APK>
```

**If a class fails to match:** rerun with `--debug` to see exactly which
signatures failed and why. Add more specific signatures or loosen over-tight
patterns, then re-test.

```bash
sigmatcher analyze --signatures sigs.yaml --debug <APK>
```

**If multiple classes match** (false positives): the signatures are too broad.
Add more signatures (AND) or make existing ones more specific.

**Check referencers:** Files with 1-2 references to the target name (cast
strings, field types) should NOT be matched. If they are, your signatures
aren't specific enough.

**Repeat until every APK produces exactly one match.**

## Reference files

- `references/SIGFILE_REFERENCE.md` — full YAML structure, fields, and matching logic
- `references/MACROS.md` — macro syntax and property table
- `references/COMMANDS.md` — command cheat sheet
- `references/CHECKLIST.md` — completion checklist
