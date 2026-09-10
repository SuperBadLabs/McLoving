#!/usr/bin/env python3
"""Refuse fixture release unless both actual containers match the private boundary."""
import argparse
import json
from pathlib import Path

RUNTIME_ID = '3b072c3e47bfa9a97dc733fc414da2005c99180f111ac0842327bd963509a1c1'
POSTGRES_ID = 'd741b376874687de90374fd34f55c6b2760e8f7bd7e4ae5cd47f50757fc08cf8'
POSTGRES_REFERENCE = 'docker.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94'
DB_WATCHDOG = ['-c', 'exec timeout -s KILL 600 /usr/local/bin/docker-entrypoint.sh postgres']
RUNNER_BODY = '''
    set -euo pipefail
    until test -f /tmp/jcomp-boundary-approved; do sleep 0.1; done
    sha256sum /bin/sh
    printf "controller-build-provenance "
    /tmp/jcomp003-target/debug/mcloving-controller build-provenance
    printf "agent-build-provenance "
    /tmp/jcomp003-target/debug/mcloving-agent build-provenance
    set +e
    /tmp/jcomp003-target/debug/jcomp003_paired --ignored --nocapture --test-threads=1
    status=$?
    printf "%s\\n" "$status" > /tmp/test-status
    sleep 600
  '''
DEFAULT_PG_CAPABILITIES = {
    'CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER', 'CAP_FSETID', 'CAP_KILL',
    'CAP_NET_BIND_SERVICE', 'CAP_SETFCAP', 'CAP_SETGID', 'CAP_SETPCAP',
    'CAP_SETUID', 'CAP_SYS_CHROOT',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def size(value):
    value = value.lower()
    for suffix, scale in [('mb', 1024 ** 2), ('gb', 1024 ** 3),
                          ('m', 1024 ** 2), ('g', 1024 ** 3)]:
        if value.endswith(suffix):
            return int(value[:-len(suffix)]) * scale
    return int(value)


def tmpfs(value, expected_size, expected_mode=None):
    options = {}
    for item in value.split(','):
        key, _, val = item.partition('=')
        require(key not in options, 'duplicate tmpfs option')
        options[key] = val
    require(set(options) <= {'rw', 'size', 'mode', 'noexec', 'nosuid', 'nodev',
                             'rprivate', 'tmpcopyup'}, 'unreviewed tmpfs option')
    require('rw' in options and size(options['size']) == expected_size, 'tmpfs bound changed')
    if expected_mode is not None:
        require(int(options.get('mode', '0'), 8) == expected_mode, 'tmpfs mode changed')
    else:
        require('mode' not in options, 'database tmpfs mode changed')


def common(container, memory, cpus, pids):
    host = container['HostConfig']
    require(host['Privileged'] is False and not host['PortBindings'] and
            host['PublishAllPorts'] is False, 'privilege or exposed host port')
    require(host['PidMode'] == 'private' and host['IpcMode'] == 'private', 'shared process namespace')
    require(not host['CapAdd'] and not host['Devices'], 'added capability or device')
    require(host['Memory'] == memory and host['MemorySwap'] == memory and
            host['NanoCpus'] == cpus * 10 ** 9 and host['PidsLimit'] == pids,
            'resource bound changed')
    require(host['LogConfig']['Type'] == 'k8s-file' and
            size(host['LogConfig']['Size']) == 8 * 1024 ** 2, 'unbounded container logs')
    require(any(limit['Name'] == 'RLIMIT_NOFILE' and limit['Soft'] == 1024 and
                limit['Hard'] == 1024 for limit in host['Ulimits']), 'descriptor bound changed')
    environment = container['Config']['Env']
    require(not any(entry.partition('=')[0].lower() in
                    {'http_proxy', 'https_proxy', 'all_proxy', 'ftp_proxy', 'no_proxy'}
                    for entry in environment), 'host proxy environment inherited')
    return host


def verify(runner, database, scratch):
    require(len(runner) == len(database) == 1, 'expected one runner and one database')
    runner, database = runner[0], database[0]
    require(runner['Image'].removeprefix('sha256:') == RUNTIME_ID, 'runtime image changed')
    require(database['Image'].removeprefix('sha256:') == POSTGRES_ID, 'database image changed')
    require(database['ImageName'] == POSTGRES_REFERENCE, 'database immutable reference changed')
    db_host = common(database, 1024 ** 3, 2, 256)
    require(db_host['NetworkMode'] == 'none', 'database has an external route')
    require(database['Mounts'] == [], 'database has a host mount')
    require(set(db_host['Tmpfs']) == {'/var/lib/postgresql/data'}, 'database tmpfs inventory changed')
    tmpfs(db_host['Tmpfs']['/var/lib/postgresql/data'], 512 * 1024 ** 2)
    # The pinned PostgreSQL entrypoint starts as root to initialize its private
    # tmpfs and drops to postgres. These default capabilities stay entirely in
    # the rootless container; this is not the product workload's capability set.
    require(database['Config']['User'] in ('', '0', '0:0'), 'database initialization user changed')
    require(set(database['EffectiveCaps']) == DEFAULT_PG_CAPABILITIES,
            'database initialization capabilities changed')
    require(database['Config']['Entrypoint'] in ('/bin/sh', ['/bin/sh']) and
            database['Config']['Cmd'] == DB_WATCHDOG, 'database lifetime watchdog changed')
    require(db_host['ReadonlyRootfs'] is False, 'database root filesystem contract changed')
    host = common(runner, 2 * 1024 ** 3, 4, 512)
    require(host['NetworkMode'] == 'container:' + database['Id'], 'runner network join changed')
    require(host['ReadonlyRootfs'] is True and 'no-new-privileges' in host['SecurityOpt'],
            'runner filesystem or privilege boundary changed')
    require(runner['EffectiveCaps'] in (None, []) and runner['Config']['User'] == '1000:1000',
            'runner privilege changed')
    require(set(host['Tmpfs']) == {'/tmp'}, 'runner tmpfs inventory changed')
    tmpfs(host['Tmpfs']['/tmp'], 512 * 1024 ** 2, 0o1777)
    expected = {'/tmp/jcomp003-target/debug': scratch / 'binaries',
                '/opt/jcomp/tracer': scratch / 'tracer', '/opt/jcomp/input.json': scratch / 'input.json'}
    mounts = runner['Mounts']
    require(len(mounts) == 3 and {mount['Destination'] for mount in mounts} == set(expected),
            'runner mount inventory changed')
    for mount in mounts:
        require(mount['Source'] == str(expected[mount['Destination']]) and
                mount['Type'] == 'bind' and mount['RW'] is False, 'runner host mount changed')
    require(runner['Config']['Entrypoint'] in ('/usr/bin/timeout', ['/usr/bin/timeout']), 'runner watchdog missing')
    command = runner['Config']['Cmd']
    require(len(command) == 6 and command[:5] == ['-k', '5', '240', '/bin/bash', '-c'] and
            command[5].strip() == RUNNER_BODY.strip(), 'runner watchdog or release gate changed')
    env = dict(item.split('=', 1) for item in runner['Config']['Env'])
    require(env.get('MCLOVING_TEST_DATABASE_URL') == 'postgres://mcloving@127.0.0.1:5432/mcloving',
            'database endpoint changed')
    require(env.get('JCOMP_INPUT') == '/opt/jcomp/input.json' and
            env.get('JCOMP_OUTPUT') == '/tmp/observations' and
            env.get('MCLOVING_CONTROLLER_BINARY') == '/tmp/jcomp003-target/debug/mcloving-controller' and
            env.get('JCOMP_STRACE') == '/opt/jcomp/tracer/observe-exec', 'runner fixture path changed')
    return 'product-boundary-ok network=private-loopback production_authority=false'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runner_inspect', type=Path)
    parser.add_argument('database_inspect', type=Path)
    parser.add_argument('scratch', type=Path)
    args = parser.parse_args()
    print(verify(json.loads(args.runner_inspect.read_text()),
                 json.loads(args.database_inspect.read_text()), args.scratch.resolve(strict=True)))


if __name__ == '__main__':
    main()
