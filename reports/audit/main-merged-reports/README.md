# Reports preserved from main

These three TSV files are exact copies from main commit
`ef47c55a85c82a78ecf15132d0b545e91c7294bf`, merged on October 15, 2026.
They preserve the separate remediation work merged through PR #3.

The detailed audit tables remain at the three corresponding paths directly under
`reports/`. Their schemas, scan evidence and counting rules differ from these
copies. Do not append or sum the two sets: some products and findings overlap,
and some original counts differ. APPLIED means a claim inherited from main;
this merge does not independently validate the upgrade or its vulnerability
reduction. In particular, the audit found remaining findings in Falco Exporter
and requires compatibility validation before its retirement.

Main's production chart settings are retained unchanged by the merge. The
original 81-product inventory is now available at `reports/cve-per-product.tsv`.
Its complete image set and original CRITICAL/HIGH counts match all 81 rows in
the audit tables. The merge also passed the existing target compatibility,
layering, exclusion and profile tests. Byte comparisons confirmed that the
archived reports and merged chart values match main exactly.
No push to main is performed as part of this merge.
