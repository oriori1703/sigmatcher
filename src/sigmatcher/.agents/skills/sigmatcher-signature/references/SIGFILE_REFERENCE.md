# Signature file reference

A signature file is a YAML list of class definitions. Each class can contain
methods, fields, and exports of its own.

## Top-level structure

```yaml
- name: "ConnectionManager"
  package: "com.example.package.network"
  signatures:
    - signature: '...'
      type: regex
      count: 1
  methods:
    - name: "read"
      signatures:
        - signature: '...'
          type: regex
  fields:
    - name: "socket"
      signatures:
        - signature: '...'
          type: regex
  exports:
    - name: "targetRef"
      signatures:
        - signature: '...'
          type: regex
```

## Fields on a definition

| Field          | Required | Description |
|----------------|----------|-------------|
| `name`         | Yes      | The deobfuscated name of the class/method/field/export |
| `package`      | No       | Only on classes. Output labeling, not a match filter |
| `signatures`   | Yes      | List of signatures that must all match (AND logic) |
| `methods`      | No       | Child method definitions |
| `fields`       | No       | Child field definitions |
| `exports`      | No       | Child export definitions. Scans parent's smali file |
| `version_range` | No      | PEP-440 specifier, e.g. `>=2.0.0, <3.0.0`. Can be a list (OR) |
| `exclude`       | No      | If true, exclude this definition from final output. Useful for helper definitions used only as macro targets |

## Signature fields

| Field            | Description |
|------------------|-------------|
| `type`           | `regex`, `glob`, or `treesitter` (treesitter not yet implemented) |
| `signature`      | The pattern. For classes/methods: match anywhere in the file. For fields/exports: must use `(?P<match>...)` capture group |
| `count`          | Match count range. Integer or `"min-max"` string. Defaults to `1` |
| `version_range`  | PEP-440 specifier(s) limiting which APK versions this signature applies to |

## Class matching logic

1. Start with all `.smali` files in the APK
2. For each signature, filter to files where the pattern appears within `count` range
3. All signatures must match the same file (AND)
4. The first line of the matching file (`.class public ...`) determines the obfuscated class name
5. `package` in the definition is used for output; defaults to the matched file's package if omitted

## Method matching

A method definition matches within the smali file of its parent class. The
signature must match anywhere in the method's body. The matching method is
identified by its `.method` declaration line.

## Field matching

A field definition matches within the smali file of its parent class. The
signature must use a `(?P<match>...)` capture group — the entire captured
string becomes the field's Java representation.

## Export matching

An export definition matches within the smali file of its parent class.
Exactly one signature per export is allowed. The signature must use a
`(?P<match>...)` capture group — the captured value becomes the export's
`.value` property, accessible as `${ParentClass.exports.exportName.value}`.
