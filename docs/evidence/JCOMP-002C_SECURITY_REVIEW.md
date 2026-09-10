# JCOMP-002C independent negative diagnostic correction

## Status and bounded result

JCOMP-002C is DONE on the protected merge and exact-main receipts recorded below. The correction aligns independently checked negative diagnostics without expanding runnable syntax. JCOMP-003 remains ACTIVE and requires a fresh reviewed compiler/runtime freeze and separate campaigns.

The historical reviewed execution candidate is `2326a63b6c52a5354a82d58aee9879db046613c9`, tree `035210fe048f45604119f796a18b47070006bff9`, based on earned predecessor closure commit `249d772072530fb511602eb16ed3a1d59732a67b` above verified runtime `44f0498fbdf3a59434176e9d09a52e1260336260`. Later evidence/documentation commits must preserve the tested compiler and policy bytes; candidate receipts do not become new-head execution receipts merely by being copied.

## Follow-up review correction: malformed interpolation prefix

PR #135 review found an additional non-corpus counterexample: a malformed first `$ ` prefix before an escaped physical newline in a triple-quoted literal. Source `2326a63` returned a later lexical exclusion, while pinned Groovy and independent Rust recognized the earlier parse error. The sealed `jcomp-002c-v1` evidence remains a source-qualified historical baseline; it does not validate this additional case or any later compiler source.

The follow-up aligns only the Clojure preflight with Rust's existing known-invalid initial-dollar-tail and initial-interpolation-prefix predicates, before marking the literal dynamic. Unknown nested expressions remain outside that bounded proof. Seven additional shared regressions cover the review case and related initial prefixes; disabling the precheck restores their failures. The V2 contract, Rust classification logic and admitted grammar are unchanged. Fresh exact-candidate results are qualified in the earned-closure section below; the original 2326 subset remains historical.

## Versioned policy and independent boundary

`JENKINS_SEQUENTIAL_DECLARATIVE_V2.md` binds the revised negative diagnostic policy at SHA-256 `264436c57b3aa82810f7041515c924b38a5a5e4be1f60fb6987151d1e8336a41`. V1 remains unchanged at `ae47b3f3cc58d6a66cec6d73832a189417864df74110c83bf1f656840c5d5dfe`; the original 23-fixture manifest remains `654898829f31872d471db88830414b23a9453e021bec281f05ac1aa4175de727`.

Source byte/text bounds and raw Unicode-introducer preflight precede a source-order lexical scan. Its first independently established malformed protected literal or lexical exclusion determines the negative diagnostic. Lexical exclusion means outside the protected lexical language, not that the entire excluded document is valid Groovy. The slash exclusion applies only at a parenthesized argument start. Flat identifier/property interpolation boundaries are recognized only to locate subsequent excluded literal-segment escapes; unknown nested-expression interiors remain unverified.

Every potentially admitted candidate still requires full Groovy parsing, bounded lexical/AST agreement, independent Rust source classification and exact output validation. No Groovy evaluation, source allowlist, admission exemption, source normalization, new executable grammar, runtime change or production authority is introduced. Definitions remain disabled; authored fixtures and original corpus identities retain separate denominators.

## Observed pre-correction failures

The original corpus capture at `2eadf80ec99f362d901a01a074b79e669a7fe3a9` used worker `08774d9d01ab47864d447f915f84bc48b424b13b844c69087ff3987a55d00380` and admission `137adcb4b9af2c24dddd5dc2bb2e281f64b8caaed2472a5bd94771482ff890ba`. Six rows remained unverified under `E_SOURCE_CLASSIFICATION`. A separate diagnostic capture preserved actual worker responses and genuine admission refusal:

| Original record | Source file | Worker observation | Rust diagnostic observation |
|---|---|---|---|
| 018 | `Romeh_spring-boot-ignite.Jenkinsfile` | unsupported / E_SOURCE_LEXICAL | Unclassified |
| 019 | `Romeh_spring-boot-sample-app.Jenkinsfile` | unsupported / E_SOURCE_LEXICAL | Unclassified |
| 023 | `SumitM01_CI-CD-for-Docker-Kubernetes-using-Jenkins.Jenkinsfile` | rejected / E_SOURCE_PARSE | Unsupported / E_SOURCE_LEXICAL |
| 065 | `eldada_jenkins-pipeline-kubernetes.Jenkinsfile` | unsupported / E_SOURCE_LEXICAL | Unclassified |
| 160 | `jussaragranja_SeleniumEasyTest2.Jenkinsfile` | unsupported / E_SOURCE_LEXICAL | Rejected / E_SOURCE_PARSE |
| 162 | `k11h-de_zap-jenkins.Jenkinsfile` | rejected / E_SOURCE_PARSE | Unsupported / E_SOURCE_LEXICAL |

All six genuine admission invocations exited nonzero. These old observations remain unverified; later corrected classifications do not rewrite them. Original sources remain under `migration/mario-jenkins-oracle-228/corpus-v1/sources/`, with 226 unchanged originals and two previously typed-redacted representations. Source paths and hashes identify the six cases without republishing duplicate source bodies.

## Exact candidate verification

The complete Rust admission package passed 34 tests across four nonempty test binaries (18 + 4 + 8 + 4), with zero failed or ignored tests; strict Clippy passed. The Clojure suite passed 13 tests and 257 assertions with zero failures or errors. Ten reduced regressions cover the observed exclusions, known malformed literals and Unicode precedence. Restoring the old worker parse order caused four failed assertions; restoring old Rust interpolation handling failed the flat GString case as Unclassified. Both mutation failures are retained separately from restored-source results.

A fresh build from the candidate Git archive produced worker `8380567bcea6319ad204adfa1c319d715a0233f451cb7bf7ddce837f874949d0` and admission `d7e9c82e7a4c5c27d9410d1508ce240adf1e3670af2afa187a0439d37d63f915`. The archived source SHA-256 is `52a07eab89d3c3d64d6458d621e14f11eaf7b9b1b867a4614d054247d0423dd9`; the original complete build inventory is `f2a447d951f3f1aebb2f60d60efa2a7cf49a8bc9a05f7042ffd1573296dff8fe`.

The fixed 23 inputs compiled twice, producing 46 matching expected responses under authored campaign SHA-256 `292ff5bab314058cbc6cdf5ed83cdc12fb00e8cb55a004b259028d10f4719954`. The independent reviewer replayed all 46 through the actual admission binary and verified unchanged admitted pipeline YAML and semantic IR hashes against the historical campaign. Disabled-definition hashes change because those bytes embed the V2 contract hash; genuine Rust admission independently reconstructs and checks the exact new disabled definitions. This expected metadata change is not executable grammar expansion.

The exact-candidate original corpus capture completed with 1 admitted, 216 unsupported, 11 rejected and zero unverified records. All 228 original identities remain intact. The six previously unverified records now have independently agreed `unsupported / E_SOURCE_LEXICAL` receipts; all other classifications are unchanged. The runtime owner and independent reviewer each replayed all 228 through the genuine admission binary; the reviewer also rehashed all 457 raw capture files. The campaign SHA-256 is `172cc8c7e429e63159464ee9efc3ca7b92185975a8fe5bc8b0a1c158e01997c2`, and the local verification receipt is `ffab35cce3a8d358ed91792c42b5198eb9e2e3f4386613445ef86e24fd343feb`. These are compile-only classifications, with zero workload executions or execution-equivalence claims.

Intermediate failed attempts remain qualified separately: an initial Clojure command used the wrong directory; an expanded passing suite initially hit the old twelve-test population assertion; an intermediate lexer syntax error was corrected before the candidate; and an initial authored comparison incorrectly required unchanged disabled-definition hashes despite their new V2 binding. The final exact-candidate checks above supersede those attempts without relabeling them as passes.

## Independent review and retained evidence

The retained [independent static review](jcomp-002c-v1/2326a63-independent-review.json) binds the exact candidate at SHA-256 `e52e5e301bdb8e4881542e32dcf96038f9c780bb5693decf0c78c18098bb50cb`. Independent build review is `73c97c3e24e873b345c27374e1cba43531c3b21b8e7990cdcbafcb124b9374dc`; independent authored replay is `b06bec8cc98b4683f123f95e801d1365dc78bf42d9fa2cc742787b6fe01b997d`. The [independent corpus review](jcomp-002c-v1/2326-corpus-final-review.json) is `271f657e8f3aac3f48478c9484d7c02d9cc4c463830aef1983abfbbcdd3bb432`.

The [bounded public evidence directory](jcomp-002c-v1/README.md) retains source/build/test/mutation summaries and review receipts, the six before/after response and admission records, and the whole 228 campaign manifest/counts. The 53-file directory’s [checksum manifest](jcomp-002c-v1/ARTIFACTS.sha256) has SHA-256 `7e6ceb456234abaed40257d3fc9c5bd4333c505eaabc8bc0ba2ac7c774fc304d` and covers only that subset. An incremental [source bundle and recovery receipt](jcomp-002c-v1/source-bundle-recovery.json) preserve exact tested source 2326 independently of future squash history; isolated recovery reproduced its commit, tree and full source archive hash.

Full authored and original-corpus response sets, the full source archive, admission executable and container images remain local custody artifacts for the durable handoff. This public subset is not a complete offline campaign replay inventory. JCOMP-003 must publish fresh full runtime/corpus evidence separately after recapture.

TM-008 and TM-020 were reviewed for the parser-resource and independent-admission boundaries above. Jointly flawed recognizers and existing host/container assumptions remain residual risks. There is no new controller, credential, scheduling, migration or production authority. The protected review, normal merge and exact-main gates below earn closure; these local observations alone did not.

## Earned closure on corrected PR #135

The final reviewed compiler source is `c94d232af0f0319585e13c72ed5d96cffe04ce33`, tree `b5f50381ad6af2183bb6d6ef56c8daee2e371723`. Independent final-source review SHA-256 is `2d1cf5f8d81b7d424a591c2868aac9b7d63c62921800a710f322bf271a6ec27b`. Fresh validation independently replayed all 17 reduced cases, all 46 preregistered fixture responses and all 228 original-corpus responses. The corpus again has 1 admitted, 216 unsupported, 11 rejected and zero unverified; all 457 raw files were checked, and response bytes match the historical 2326 population. Fresh corpus campaign SHA-256 is `55bf3659ce58cb2cc8daeba2d471ac18f74e0e4b4500a8c5dba5dd5a5328787c`. Unknown punctuation or nested interpolation, including the later `$)` review probe, remains intentionally unverified rather than gaining a generic denial shortcut. No runnable grammar or runtime authority expands.

PR #135 normally merged as signed `01137b54b8fbefdc0deb0214a5d4d8979a773575` with the exact reviewed tree above and sole parent `44f0498fbdf3a59434176e9d09a52e1260336260`. Exact-main Foundation [34450761533](https://github.com/SuperBadLabs/McLoving/actions/runs/34450761533) attempt 1 and actual native Windows [34450761576](https://github.com/SuperBadLabs/McLoving/actions/runs/34450761576) attempt 1 succeeded. The byte-preserved [post-merge audit](JCOMP-002C_CLOSURE.json) has SHA-256 `d10d2965828e40d17673a711cf181a6033aa0a61c2ccc20c920ff9a6605487e6`. This subsequent bookkeeping earns closure; it does not relabel historical candidate or failed CI evidence. Fresh c94 raw evidence remains in the durable mission custody; the immutable public jcomp-002c-v1 subset still represents 2326 only. JCOMP-003 must regenerate fresh compiler and runtime captures on its reviewed successor freeze.
