# ADR 0007: Strict YAML native authoring

Status: Accepted

Native pipelines use a restricted YAML 1.2 subset. Duplicate keys, anchors,
aliases, merge keys, custom tags, directives, complex keys, multiple documents,
implicit timestamps, and unknown fields are rejected. YAML compiles to IR and
is never interpreted by the runtime.
