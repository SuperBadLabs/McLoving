# Qwen corpus draft, independently reviewed

Provisional static contract reading only. Not Jenkins validity, Groovy parsing, compiler admission/classification, runtime evidence, or a corpus-wide coverage result. No source was executed or changed.

Service base URL: `http://127.0.0.1:8000/v1`. The model-list endpoint `http://127.0.0.1:8000/v1/models` and the response both identified `qwen3.8-flash-next` (llamacpp). Request cap: 2,000 output tokens; timeout: 55 seconds; temperature: 0.1; thinking disabled. Observed usage: 2,712 prompt + 1,182 completion tokens. Only the eight public repository source representations below were sent; no private inventory or Jenkins console evidence.

Contract: docs/architecture/JENKINS_SEQUENTIAL_DECLARATIVE_V1.md, SHA256 ae47b3f3cc58d6a66cec6d73832a189417864df74110c83bf1f656840c5d5dfe.

All quoted Qwen citations were checked against exact repository lines. The eight provisional in/out shape assessments stand, with two corrections: devops-ws line8 is a dynamic Groovy property argument (`env.CHANGE_ID`), not string interpolation; Qwen’s C052 limitation “None” is replaced by the explicit no-validation/no-runtime limitation above. Shell `make`/`mvn` text is not itself a syntax blocker; required external tools provide no execution guarantee.

Representation custody: each selected corpus-index row declares redacted=false and jenkins_source_normalization=none, and source/repository/Jenkins digests are equal. These eight facts do not apply to other redacted or normalized corpus rows. Existing historical statuses/receipts were not recomputed or overwritten. NOASSERTION licensing remains evidence-only, not a new license grant.

## cinqict_jenkinsdev

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/cinqict_jenkinsdev.Jenkinsfile`

SHA256: `666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100`; bytes=177; commit=`d20369f19c12899e2f3bc5c8fbce7e7b81752fb7`; license=MIT.

Provisional manual shape: **supported_shape**.

- Lines3–11 show pipeline/agent-any/stages/one stage/one literal sh; line8 script is `echo "Hello World"`; line1 initial Groovy shebang is allowed. No unsupported construct identified by this static review.

## devops-ws_learn-pipeline-java

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/devops-ws_learn-pipeline-java.Jenkinsfile`

SHA256: `38d8798a5d4d068f5b12ffde42cbc35b6c51621b9eb2ba042f31de76ff013f95`; bytes=466; commit=`57a532912f1826de3c6569a05b4bd68fd1c81c86`; license=MIT.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line7, `echo 'first stage'`.

- Additional blocker: line8, `echo env.CHANGE_ID`.

- Additional blocker: line15, `archiveArtifacts artifacts: 'log.txt', followSymlinks: false`.

- Additional blocker: line22, `archiveArtifacts artifacts: 'three.txt', followSymlinks: false`.

Line8 is a property-expression argument, not a GString. First direct echo line7 already lies outside literal-sh-only steps.

## charlires_golang-docker-jenkins

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/charlires_golang-docker-jenkins.Jenkinsfile`

SHA256: `35091bc2909001e1fa14b136e30a6cf983406342c7a3ab6924f08b225c05f1a9`; bytes=439; commit=`083734415a092b42f2194eefff2af6936566890d`; license=Apache-2.0.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line15, `junit 'report/report.xml'`.

## TechPrimers_jenkins-example

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/TechPrimers_jenkins-example.Jenkinsfile`

SHA256: `3a6417cae39894496497d7e0f5782bb0fa381b3695c9ae0653e6706e888b321c`; bytes=608; commit=`03df67aeee07fa96c3bd8660b8f69fb1221fbd29`; license=NOASSERTION.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line8, `withMaven(maven : 'maven_3_5_0')`.

- Additional blocker: line17, `withMaven(maven : 'maven_3_5_0')`.

- Additional blocker: line26, `withMaven(maven : 'maven_3_5_0')`.

## sixeyed_jenkins-pipeline-demos

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/sixeyed_jenkins-pipeline-demos.Jenkinsfile`

SHA256: `dec6273f52492c13c0ccff4c35737a90aa42563e5d6a16aebde5e05725b37b40`; bytes=360; commit=`bf2eb40a98785e156885cdb1f28548448741f773`; license=NOASSERTION.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line4, `environment {`.

- Additional blocker: line11, `echo "This is build number $BUILD_NUMBER of demo $DEMO"`.

## allcloud-io_jenkins-pipeline-tutorial

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/allcloud-io_jenkins-pipeline-tutorial.Jenkinsfile`

SHA256: `7bf47940d691f7f0e8514f72f92dc2935e38adc229a22d77124a46f305a28400`; bytes=942; commit=`d50fedb0ccca47627d3d7e0bb564e3ad334288a7`; license=NOASSERTION.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line8, `environment {`.

- Additional blocker: line23, `echo 'This is a sample stage'`.

## buildit_jenkins-pipeline-libraries

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/buildit_jenkins-pipeline-libraries.Jenkinsfile`

SHA256: `894ac23ae5e37840615c979b33bff728c157669b0bf8bfb74f1f4def7d828dee`; bytes=546; commit=`fe3ef22d856cf6f2e37e76890aa3b70ffc7313b3`; license=NOASSERTION.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line3, `options {`.

- Additional blocker: line8, `triggers {`.

- Additional blocker: line11, `tools {`.

- Additional blocker: line24, `post {`.

The nested junit at line26 is also outside subset; this supplements Qwen’s directive list. No inference about generic Groovy/Jenkins acceptance is made.

## cvitter_jenkins-pipeline-examples

Path: `migration/mario-jenkins-oracle-228/corpus-v1/sources/cvitter_jenkins-pipeline-examples.Jenkinsfile`

SHA256: `4c7a5ac0431ca337c635678d5320fc987e232ed5336f0c9cee956ec08b3f7fe1`; bytes=358; commit=`3093b478bf713c23b056b6f0162e87ebf3f9ee04`; license=Apache-2.0.

Provisional manual shape: **outside_subset**.

- First source-order blocker: line10, `echo 'Hello World!'`.

## Review limits and retained drafts

These are deliberately selected nearest-shape examples, not a representative statistical sample. Do not report “1/8 supported” as measured compiler coverage or extrapolate to 228. Future compiler classification must read every exact original representation, retain source/redaction/normalization bindings, and use independent worker/Rust agreement under a separate authorized campaign.

The original raw service transcript was temporary and is not a dependency of this handoff. This preserved note contains the agent-reviewed citations and corrections only. Reverify the model, source digests and citations before reuse.


Source references in this planning note describe repository commit `904fd1fed083cd17a6fc371e0a300c3696d93483` (tree `26240208f51f6028bf6bb6e619a2dcd5d19555f0`). Re-resolve paths and line numbers on the successor head. Planning and historical tool observations are not new runtime evidence.
