#!/usr/bin/env python3
"""Emit a bounded, secret-free view of the live Mario source boundary."""

import json
import subprocess


CONTAINER = "jenkins-oracle-228"
NETWORK = "jenkins-oracle-net"
IMAGE = (
    "docker.io/jenkins/jenkins@sha256:"
    "f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02"
)


def output(*arguments: str) -> str:
    return subprocess.check_output(arguments, text=True).strip()


def require(condition: bool) -> None:
    if not condition:
        raise SystemExit("live source containment does not match the closed boundary")


container = json.loads(output("podman", "inspect", CONTAINER))[0]
network = json.loads(output("podman", "network", "inspect", NETWORK))[0]
members = sorted(
    line
    for line in output(
        "podman", "ps", "--filter", f"network={NETWORK}", "--format", "{{.Names}}"
    ).splitlines()
    if line
)
mounts = sorted(
    (mount["Type"], mount["Destination"], bool(mount["RW"]))
    for mount in container["Mounts"]
)
networks = sorted(container["NetworkSettings"]["Networks"])
proxy_environment_names = sorted(
    entry.split("=", 1)[0]
    for entry in container["Config"]["Env"]
    if "proxy" in entry.split("=", 1)[0].lower()
)

require(container["ImageName"] == IMAGE)
require(container["State"]["Status"] == "running")
require(container["HostConfig"]["ReadonlyRootfs"] is True)
require(container["HostConfig"]["Privileged"] is False)
require((container["HostConfig"].get("CapAdd") or []) == [])
require(container["HostConfig"].get("Devices", []) == [])
require(container["HostConfig"]["SecurityOpt"] == ["no-new-privileges"])
require(container["HostConfig"]["NetworkMode"] == "bridge")
require(container["HostConfig"]["PidMode"] == "private")
require(
    container["HostConfig"]["PortBindings"]
    == {"8080/tcp": [{"HostIp": "100.127.170.90", "HostPort": "18080"}]}
)
require(networks == [NETWORK])
require(network["internal"] is True)
require(network["driver"] == "bridge")
require(members == [CONTAINER])
require(proxy_environment_names == [])
require(mounts == [
    ("bind", "/oracle/corpus", False),
    ("bind", "/usr/share/jenkins/ref/plugins", False),
    ("bind", "/var/jenkins_home", True),
])

binding = {
    "schema": "mcloving.shadow001.source-boundary/v1",
    "container": CONTAINER,
    "image": IMAGE,
    "running": True,
    "read_only_root": True,
    "privileged": False,
    "added_capabilities": 0,
    "devices": 0,
    "no_new_privileges": True,
    "pid_namespace": "private",
    "mounts": [
        {"type": kind, "destination": destination, "writable": writable}
        for kind, destination, writable in mounts
    ],
    "network": NETWORK,
    "network_internal": True,
    "network_members": members,
    "proxy_environment_names": proxy_environment_names,
    "reachable_connector_peers": 0,
    "production_endpoint_mappings": 0,
}
print(
    "SHADOW001_SOURCE_BOUNDARY="
    + json.dumps(binding, sort_keys=True, separators=(",", ":"))
)
