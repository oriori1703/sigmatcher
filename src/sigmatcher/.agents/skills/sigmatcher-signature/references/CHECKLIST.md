# Completion checklist

- [ ] Ensure cache exists for all APK versions (`sigmatcher cache dir <APK>`)
- [ ] Find candidate files with `rg -cF` — identify target vs referencers
- [ ] Compare strings across versions — pick stable, unique signatures
- [ ] Verify uniqueness globally (`rg -cF` across all smali)
- [ ] Sort signatures by selectivity in the YAML
- [ ] Test against every APK version — exactly one match each
