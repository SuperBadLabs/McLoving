# ADR 0004: Agent protocol and execution boundary

Status: Accepted

Rust agents connect outbound through mTLS and a versioned Protobuf/gRPC
protocol. Accepted work is journaled locally before execution. Linux uses
process groups and cgroups; Windows uses native processes and Job Objects.
Java is not required on agents.
