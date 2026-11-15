# attacks/ - payload corpus and injection tooling (owner: Fatima)

- `taxonomy/fields.yaml` - trusted vs untrusted fields per log source
- `payloads/` - payload templates (YAML) per category
- `generators/` - web and DNS log generators, injection script
- Output corpus goes to `data/corpus/` and is versioned with Git tags (`corpus-v0.1`, ...).

Seeds are fixed so the corpus can be regenerated identically.
