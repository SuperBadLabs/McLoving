# HYG-003 exact owner-archive fixtures

`index.json` binds seven original staged files to their source paths, lengths
and SHA-256 values. Three complete original manifests are retained in lossless
gzip form; tests verify the decompressed original bytes. Four complete original
Markdown files reproduce the four observed old-checker false alarms. The
production reviewed registry, rather than a synthetic pin override, is used
for this integration replay.

The production scope contains 107 listed Markdown files (6 + 42 + 59). This
fixture is deliberately a partial seven-file mirror, not complete payload
recovery or an actual owner-tree proof. It grants no authorship or operational
authority. All adversarial modifications happen in disposable test copies;
original owner archives remain untouched. The original staging/provenance is
recorded by root in HYG-003/local-owner-archive-assessment.json and
owner-archive-fixture-staging/staging.json. Git-history red/green fixtures remain
separate in ../stale-claims.json.
