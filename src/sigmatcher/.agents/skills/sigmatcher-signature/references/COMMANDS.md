# Commands reference

## Schema

```bash
sigmatcher schema --output definitions.schema.json
```

## Analyze

```bash
sigmatcher analyze --signatures sigs.yaml <APK>
sigmatcher analyze --signatures sigs.yaml --debug <APK>
sigmatcher analyze --signatures sigs.yaml --output-format enigma <APK>
```

## Cache

```bash
sigmatcher cache dir <APK>
sigmatcher cache clear <APK>
```

## Search smali (inside the cache dir)

```bash
rg -cF 'ClassName' <cachedir>/apktool/ | sort -t: -k2 -rn
rg -F 'ClassName' <cachedir>/apktool/
```
