# Crucible corpus — pre-registered selection method

Fixed BEFORE any result was seen, per the discipline agreed with the pit boss.

Frame:  public GitHub repositories, not forks, containing a file named exactly
        `Jenkinsfile` at the repository ROOT.
Query:  gh search code --filename Jenkinsfile   (GitHub code search, best-match order)
Filter: path == "Jenkinsfile" exactly; isFork == false; distinct nameWithOwner
Target: first 100 distinct repositories in the order GitHub returns them
Excl.:  recorded with reason, never silently dropped

This is NOT a random sample of Jenkins usage. It is GitHub's best-match ordering
over public repos, which over-represents documentation/example projects and
under-represents private enterprise pipelines (the population most likely to use
shared libraries and plugins). Stated so the denominator is not mistaken for the
ecosystem.

## Method revision (recorded, not hidden)

The pre-registered code-search query failed in practice: GitHub's `--filename`
match is fuzzy and returned `Jenkinsfile2.txt`, `jenkinsFile.txt`,
`JENKINSFILE.txt` and similar. Of 100 results only 3 had basename exactly
`Jenkinsfile`.

Replacement method, fixed before results were seen:
  1. Build a candidate pool from GitHub REPOSITORY search across recorded
     queries (below), collecting non-fork repos with metadata.
  2. Probe each candidate for a root `Jenkinsfile` via
     raw.githubusercontent.com (free, does not consume API quota).
  3. Take repos returning HTTP 200 until 100 are collected.
  4. Record every candidate probed and every exclusion reason.
