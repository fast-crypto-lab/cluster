#!/usr/bin/env python3

import json
import os
import distro
import re
import sys

from os.path import dirname, realpath
from subprocess import DEVNULL, PIPE, run
from functools import lru_cache


##############################################################################


# Main entry point
def main(argv):
    assert_good_environment()
    load_fcl_json_to_global()
    if len(argv) != 2:
        error()
        error('Usage:')
        error('\t{} lock'.format(sys.argv[0]))
        error('\t{} check-this-host-in-json'.format(sys.argv[0]))
        error('\t{} check-json-applicability'.format(sys.argv[0]))
        error('\t{} apply-json'.format(sys.argv[0]))
        error('\t{} unlock'.format(sys.argv[0]))
        error()
        sys.exit(1)
    elif argv[1] == 'lock':
        main_lock()
    elif argv[1] == 'check-this-host-in-json':
        main_check_this_host_in_json()
    elif argv[1] == 'check-json-applicability':
        main_check_json_applicability()
    elif argv[1] == 'apply-json':
        main_apply_json()
    elif argv[1] == 'unlock':
        main_unlock()
    else:
        error('unknown subcommand "{}"'.format(argv[1]))
        sys.exit(1)


def assert_good_environment():
    # Ensure you are root
    assert os.getuid() == 0
    # Ensure you are running Python 3.9 (or later)
    assert sys.version_info.major == 3
    assert sys.version_info.minor >= 12
    # Ensure you are running this on a Ubuntu 22.04 server
    assert distro.linux_distribution()[0] == 'Ubuntu'
    assert distro.linux_distribution()[1].startswith('24.04')


def load_fcl_json_to_global():
    global FCL
    FCL = read_fcl_json(dirname(realpath(sys.argv[0])) + '/cluster-info/fcl.json')


##############################################################################


def main_lock():
    lock_success = create_file_exclusively('/fcl-cluster-maintenance.lock')
    if not lock_success:
        sys.exit(1)


def upload_to_gist(content, *, filename='gistfile1.txt', shorten_url=False):
    assert type(content) is str
    assert type(filename) is str
    postbody = json.dumps(
        { "files": { filename: { "content": content } } } ).encode()
    curl_result = sh([
        'curl',
        '--fail', '--silent', '--show-error', '--location', '--max-time', '8',
        '--request', 'POST', '--header', 'Content-Type: application/json',
        '--data', '@-', '--output', '-', 'https://api.github.com/gists',
    ], shell=False, input=postbody)
    if curl_result.returncode != 0:
        raise RuntimeError('fail to upload file to GitHub Gist')
    gistid = json.loads(curl_result.stdout.decode())['id']
    file_url = ('https://gist.githubusercontent.com/raw/{gistid}/{filename}'
            .format(gistid=gistid, filename=filename))
    if not shorten_url:
        return file_url
    try:
        timestamp = (sh('TZ=Asia/Taipei date +%y%m%d-%H%M%S')
                        .stdout.decode().strip())
        rand_digits = '{:03d}'.format(int.from_bytes(os.urandom(2),'big')%1000)
        nonce = timestamp + '-' + rand_digits
        return git_io_shorten(file_url, nonce + '-' + filename)
    except:
        return file_url


def git_io_shorten(url, code):
    assert type(url) is str
    assert type(code) is str
    curl_result = sh([
        'curl',
        '--fail', '--silent', '--show-error', '--location', '--max-time', '8',
        '--request', 'POST', '--header', 'Content-Type: multipart/form-data',
        '--form', 'url={}'.format(url),
        '--form', 'code={}'.format(code),
        '--include',
        '--output', '-',
        'https://git.io/',
    ], shell=False)
    if curl_result.returncode != 0:
        raise RuntimeError('fail to shorten a URL using git.io')
    lines = curl_result.stdout.decode().splitlines()
    loc_line = next(line for line in lines if line.startswith('Location:'))
    matched = re.fullmatch('^location\s*:\s*(\S*)$', loc_line, re.I)
    if matched:
        return matched.group(1)
    else:
        raise RuntimeError('fail to shorten a URL using git.io')


def main_check_this_host_in_json():
    hostname = get_this_hostname()
    if not re.fullmatch('^[a-z][a-z0-9]{1,30}$', hostname):
        error('the hostname of this machine is illegal')
        sys.exit(1)
    elif hostname not in (h['name'] for h in FCL['hosts']):
        conflicting_lan_addresses = [
            i for i in all_ipv4_addresses() if
            i.startswith('10.3.2.') and i in (
                h['private-ip'] for h in FCL['hosts']
            )
        ]
        assert (len(conflicting_lan_addresses) == 0), (
            'conflicting LAN IPv4 address: ' + conflicting_lan_addresses)
        new_host_file = '\n'.join(
            ['private-ip none', 'public-ip-port WWW.XXX.YYY.ZZZ:PPPPP']
            + all_host_public_keys('127.0.0.1', 22)
            + [''])
        print('')
        print('It seems that this machine is not declared in fcl.json yet...')
        print('You should recompile fcl.json after'
              ' putting a new host file "{}" like this:'
              .format(hostname))
        print()
        print('-----BEGIN SAMPLE FILE {}-----'.format(hostname))
        print(new_host_file, end='')
        print('-----END SAMPLE FILE {}-----'.format(hostname))
        print()
        #print('Uploading the above sample file...', flush=True, end='')
        #url = upload_to_gist(new_host_file, filename=hostname, shorten_url=True)
        #print('  DONE')
        #print('The URL for the above sample file is:')
        #print()
        #print('\t' + url)
        #print()
    else:
        record = next(h for h in FCL['hosts'] if h['name'] == hostname)
        name = record['name']
        pr_i = record['private-ip']
        pu_i = record['public-ip-port'].split(':')[0]
        pu_p = record['public-ip-port'].split(':')[1]
        keys = record['public-keys']
        assert (pr_i is None or has_ipv4_address(pr_i)), (
            'the host "{name}" must have an IPv4 address "{addr}"'
            ' according to fcl.json').format(name=name, addr=pr_i)
        assert matches_host_public_keys(keys), (
            'the host "{name}" must have the same sshd host public keys'
            ' as listed in fcl.json').format(name=name)
        assert (pr_i is None or sshd_is_reachable(keys, pr_i, 22)), (
            'the host "{name}" must be reachable at {addr}:22'
            ' according to fcl.json').format(name=name, addr=pr_i)
        assert sshd_is_reachable(keys, pu_i, pu_p), (
            'the host "{name}" must be reachable at {addr}:{port}'
            ' according to fcl.json').format(name=name, addr=pu_i, port=pu_p)


def main_check_json_applicability():
    assert group_exists_or_is_creatable('fclusers', 10000), (
            'cannot create group fclusers (gid=10000)')
    assert group_exists_or_is_creatable('fcladmins', 19999), (
            'cannot create group fcladmins (gid=19999)')
    existing_users_with_uid_in_range = [
        u for u in all_users() if
        (lambda name, uid, gid, home: (
            10000 <= uid <= 19999
        ))(*u)
    ]
    existing_usernames = [u[0] for u in existing_users_with_uid_in_range]
    all_usernames_declared_in_json = [u['name'] for u in FCL['users']]
    for name, uid, gid, home in existing_users_with_uid_in_range:
        assert (name in all_usernames_declared_in_json), (
                'user {name}(uid={uid}) exists,'
                ' but it is not declared in fcl.json'
                ).format(name=name, uid=uid)
        assert ((name, uid) in ((u['name'], u['id']) for u in FCL['users'])), (
                'user {name} has unexpected uid={uid}'
                ).format(name=name, uid=uid)
        assert (gid == 10000), (
                'user {name}(uid={uid}) has unexpected default group id {gid}'
                ).format(name=name, uid=uid, gid=gid)
        assert (home == '/home/' + name), (
                'user {name}(uid={uid}) has unexpected home directory {home}'
                ).format(name=name, uid=uid, home=home)
        assert (sh(
            'test ! -L /home/{name} -a -d /home/{name}'.format(name=name)
        ).returncode == 0), (
            'user {name} exist, but /home/{name} is not a directory'
        ).format(name=name)
    to_be_created_usernames = list(
            set(all_usernames_declared_in_json) - set(existing_usernames))
    for name in to_be_created_usernames:
        assert (sh(
            'test ! -L /home/{name} -a ! -e /home/{name}'.format(name=name)
        ).returncode == 0), (
            'user {name} does not exist, but /home/{name} does'
        ).format(name=name)


def _shell_command_to_ensure_group(groupname, groupid):
    assert type(groupname) is str
    assert re.fullmatch('^[a-z][a-z0-9]{1,30}$', groupname)
    assert type(groupid) is int
    assert 10000 <= groupid <= 19999
    pipeline_a = (
        'getent group | cut -d : -f 1,3 | grep -q ^{groupname}:{groupid}$'
        ).format(groupname=groupname, groupid=groupid)
    pipeline_b = (
        'groupadd -g {groupid} {groupname}'
        ).format(groupname=groupname, groupid=groupid)
    return '{a} || {b} || {a}'.format(a=pipeline_a, b=pipeline_b)


def _shell_command_to_ensure_user(username, userid):
    assert type(username) is str
    assert re.fullmatch('^[a-z][a-z0-9]{1,30}$', username)
    assert type(userid) is int
    assert 10000 <= userid <= 19999
    pipeline_a = (
        'getent passwd'
        ' | cut -d : -f 1,3,4,6'
        ' | grep -q ^{username}:{userid}:10000:/home/{username}$'
        ).format(username=username, userid=userid)
    pipeline_b = (
        'useradd -u {userid} -g 10000 -m -s /bin/bash {username}'
        ).format(username=username, userid=userid)
    return '{a} || {b} || {a}'.format(a=pipeline_a, b=pipeline_b)


def main_apply_json():
    # Assuming no other processes is making changes to:
    #   /etc/group
    #   /etc/gshadow
    #   /etc/passwd
    #   /etc/shadow
    #   /home/$USER for each $USER
    #   /etc/ssh/user_authorized_keys/$USER for each $USER
    #   /etc/sudoers.d/fcladmins
    #   /etc/hosts
    #   /etc/ssh/shosts.equiv
    #   /etc/ssh/ssh_config
    #   /etc/ssh/ssh_known_hosts
    #   /etc/ssh/sshd_config
    users = FCL['users']

    # ensure group fclusers (10000)
    assert sh(
        _shell_command_to_ensure_group('fclusers', 10000)
    ).returncode == 0, 'failed to create group fclusers'

    # ensure group fcladmins (19999)
    assert sh(
        _shell_command_to_ensure_group('fcladmins', 19999)
    ).returncode == 0, 'failed to create group fcladmins'

    # ensure directory /etc/ssh/user_authorized_keys/
    assert sh(
        'mkdir -p /etc/ssh/user_authorized_keys'
    ).returncode == 0, 'failed to create /etc/ssh/user_authorized_keys/'

    # for each user declared in fcl.json
    for user in users:
        user_id          = user['id']
        user_name        = user['name']
        user_permit_sudo = user['permit-sudo']
        user_public_keys = user['public-keys']

        # ensure the user exists and is in good state on this machine
        cmd = _shell_command_to_ensure_user(user_name, user_id)
        user_created = sh(cmd).returncode == 0
        assert user_created, 'failed to create user {}'.format(user_name)

        # put user public keys
        userkeys = '/etc/ssh/user_authorized_keys/{}'.format(user_name)
        userkeys_tmp = userkeys + '.swap'
        with open(userkeys_tmp, 'wb') as f:
            f.write('\n'.join(user_public_keys + ['']).encode())
            f.flush()
            os.fsync(f.fileno())
        os.rename(userkeys_tmp, userkeys)

    # for each existing file under /etc/ssh/user_authorized_keys/
    for filename in os.listdir('/etc/ssh/user_authorized_keys'):
        if filename not in (u['name'] for u in users):
            os.remove('/etc/ssh/user_authorized_keys/{}'.format(filename))

    # ensure sudo permission
    fcladmins_members = [user['name'] for user in users if user['permit-sudo']]
    assert sh(
        'gpasswd --members "' + ','.join(fcladmins_members) + '" fcladmins'
    ).returncode == 0, 'failed to update fcladmins member list'
    assert sh(
        'echo "%fcladmins ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/fcladmins'
        ' && chown -R 0:0 /etc/sudoers.d'
        ' && chmod -R 440 /etc/sudoers.d'
        ' && chmod    755 /etc/sudoers.d'
    ).returncode == 0, 'failed to update /etc/sudoers.d/fcladmins'


    hosts = FCL['hosts']

    # What is the short hostname of this machine?
    this_hostname = get_this_hostname()

    # Monkey patching... if this host is not declared in fcl.json yet...
    if this_hostname not in (h['name'] for h in hosts):
        # What IPv4 addresses does this machine currently have?
        this_addresses = all_ipv4_addresses()
        candidates = [a for a in this_addresses if a.startswith('10.3.2.')]
        private_ip = candidates[0] if len(candidates) == 1 else None
        # Append the entry for this host
        hosts.append({
            'name': this_hostname,
            'private-ip': private_ip,
            'public-ip-port': '127.0.0.1:22',
            'public-keys': all_host_public_keys('127.0.0.1', 22)
        })

    # Is this host inside the 10.3.2.0/24 LAN?
    this_in302 = (
        next(h for h in hosts if h['name'] == this_hostname)
        )['private-ip'] is not None

    put_file('/etc/hosts', generate_hosts(this_hostname, this_in302))
    put_file('/etc/ssh/shosts.equiv', generate_shosts_equiv())
    put_file('/etc/ssh/ssh_config', generate_ssh_config(this_hostname, this_in302))
    put_file('/etc/ssh/ssh_known_hosts', generate_ssh_known_hosts(this_hostname))
    put_file('/etc/ssh/sshd_config', generate_sshd_config())
    assert sh('systemctl restart ssh').returncode == 0, 'failed to restart ssh service'


def main_unlock():
    remove_file('/fcl-cluster-maintenance.lock')


##############################################################################


def sh(cmd, *, shell=True, input=None):
    return run(cmd, shell=shell, input=input, stdout=PIPE, stderr=PIPE)


@lru_cache(maxsize=None)
def get_this_hostname():
    return sh('hostname').stdout.decode().splitlines()[0]


@lru_cache(maxsize=None)
def all_ipv4_addresses():
    return [
        re.search('inet ([0-9.]*)/', line).group(1)
        for line in sh('ip a | grep -w inet').stdout.decode().splitlines()
    ]


@lru_cache(maxsize=None)
def all_groups():
    return [
        (lambda name, gid: [name, int(gid)])(*line.split(':'))
        for line in sh('getent group | cut -d: -f1,3')
                .stdout.decode().splitlines()
    ]


@lru_cache(maxsize=None)
def all_users():
    return [
        (lambda name, uid, gid, home:
            [name, int(uid), int(gid), home]
        )(*line.split(':'))
        for line in sh('getent passwd | cut -d: -f1,3,4,6')
                .stdout.decode().splitlines()
    ]


@lru_cache(maxsize=None)
def all_host_public_keys(addr, port):
    cmd = 'ssh-keyscan -T 3 -p {port} {addr}'.format(addr=addr, port=port)
    return sorted(
        [
            ' '.join(line.split(' ')[1:])
            for line in sh(cmd).stdout.decode().splitlines()
        ], key=(
            lambda s:
                ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa']
                .index(s.split(' ')[0])
        )
    )


def has_ipv4_address(addr):
    return addr in all_ipv4_addresses()


def matches_host_public_keys(expected_keys):
    return set(all_host_public_keys('127.0.0.1', 22)) == set(expected_keys)


def sshd_is_reachable(expected_keys, addr, port):
    fetched_keys = all_host_public_keys(addr, port)
    return set(fetched_keys) == set(expected_keys)


def group_exists_or_is_creatable(name, gid):
    groupsA = [g for g in all_groups() if g[0] == name or  g[1] == gid]
    groupsB = [g for g in all_groups() if g[0] == name and g[1] == gid]
    return len(groupsA) == 0 or len(groupsA) == len(groupsB) == 1


def create_file_exclusively(filename):
    try:
        f = open(filename, 'x')
    except:
        return False
    else:
        f.close()
        return True


def remove_file(filename):
    try:
        os.remove(filename)
    except:
        pass


def error(msg=''):
    sys.stdout.flush()
    print(msg, file=sys.stderr, flush=True)


##############################################################################


def generate_hosts(this_hostname, this_in302):
    entry = lambda a, n: '{a:16}{n}\n'.format(a=a, n=n)
    lines = [
        '# THIS FILE IS AUTO GENERATED\n',
        '# YOU SHALL NOT EDIT IT MANUALLY\n',
        '# ALL CHANGES WILL BE OVERWRITTEN\n',
        '\n',
        entry('127.0.0.1', 'localhost'),
        entry('127.0.1.1', this_hostname),
        '\n',
        entry('::1', 'localhost ip6-localhost ip6-loopback'),
        entry('ff02::1', 'ip6-allnodes'),
        entry('ff02::2', 'ip6-allrouters'),
    ] + ([] if not this_in302 else ['\n'] + [
        entry(h['private-ip'], h['name'])
        for h in FCL['hosts'] if h['private-ip'] is not None
    ]) + (['\n'] + [
        entry(h['public-ip-port'].split(':')[0], h['name'])
        for h in FCL['hosts'] if (h['private-ip'] is None) and (h['public-ip-port'].split(':')[1] == '22')
    ]) + [
        '\n',
        '# CIC License Servers\n',
        '140.126.24.16   lshc\n',
        '140.110.140.29  lstc\n',
        '140.110.127.149 lstn\n',
        '140.126.24.10   lscic\n',
        '140.112.20.58   lsntu\n',
        '140.115.71.66   lsncu\n',
        '140.113.202.151 lsnctu\n',
        '140.120.90.46   lsnchu\n',
        '140.116.49.24   lsncku\n',
    ]
    return ''.join(lines).encode()

def generate_shosts_equiv():
    lines = [
        '# THIS FILE IS AUTO GENERATED\n',
        '# YOU SHALL NOT EDIT IT MANUALLY\n',
        '# ALL CHANGES WILL BE OVERWRITTEN\n',
        '\n',
        'localhost\n',
        ] + [h['name'] + '\n' for h in FCL['hosts']]
    return ''.join(lines).encode()

def generate_ssh_config(this_hostname, this_in302):
    lines = [
        '# THIS FILE IS AUTO GENERATED\n',
        '# YOU SHALL NOT EDIT IT MANUALLY\n',
        '# ALL CHANGES WILL BE OVERWRITTEN\n',
        '\n',
        '# Enable /usr/lib/openssh/ssh-keysign\n',
        'EnableSSHKeysign yes\n',
        '\n',
    ]
    for h in FCL['hosts']:
        h_name = h['name']
        h_pr_a = h['private-ip']
        h_pu_a = h['public-ip-port'].split(':')[0]
        h_pu_p = h['public-ip-port'].split(':')[1]
        if h_name == this_hostname:
            lines += [
                'Match originalhost localhost,' + h_name + '\n',
                '    HostKeyAlias localhost\n',
                '    HostName 127.0.0.1\n',
                '    Port 22\n',
                '    StrictHostKeyChecking yes\n',
                '    HostbasedAuthentication yes\n',
                '\n',
            ]
        elif this_in302 and h_pr_a:
            lines += [
                'Match originalhost ' + h_name + '\n',
                '    HostKeyAlias ' + h_name + '\n',
                '    HostName ' + h_pr_a + '\n',
                '    Port 22\n',
                '    StrictHostKeyChecking yes\n',
                '    HostbasedAuthentication yes\n',
                '\n',
            ]
        else:
            lines += [
                'Match originalhost ' + h_name + '\n',
                '    HostKeyAlias ' + h_name + '\n',
                '    HostName ' + h_pu_a + '\n',
                '    Port ' + h_pu_p + '\n',
                '    StrictHostKeyChecking yes\n',
                '    HostbasedAuthentication yes\n',
                '\n',
            ]
    lines += [
        '# Provide some sane defaults for our users\n',
        'Match all\n',
        '    CheckHostIP no\n',
        '    SendEnv LANG LC_*\n',
    ]
    return ''.join(lines).encode()

def generate_ssh_known_hosts(this_hostname):
    lines = [
        '# THIS FILE IS AUTO GENERATED\n',
        '# YOU SHALL NOT EDIT IT MANUALLY\n',
        '# ALL CHANGES WILL BE OVERWRITTEN\n',
        '\n',
        ]
    for h in FCL['hosts']:
        lines += (
            '{name} {k}\n'.format(k=k, name=h['name']+(
                ',localhost' if h['name'] == this_hostname else ''
            )) for k in h['public-keys']
        )
    return ''.join(lines).encode()

def generate_sshd_config():
    lines = [
        '# THIS FILE IS AUTO GENERATED\n',
        '# YOU SHALL NOT EDIT IT MANUALLY\n',
        '# ALL CHANGES WILL BE OVERWRITTEN\n',
        '\n',
        '# Ubuntu 16.04 openssh-server defaults\n',
        'UsePrivilegeSeparation yes\n',
        'ChallengeResponseAuthentication no\n',
        'X11Forwarding yes\n',
        'PrintMotd no\n',
        'AcceptEnv LANG LC_*\n',
        'Subsystem sftp /usr/lib/openssh/sftp-server\n',
        'UsePAM yes\n',
        '\n',
        '# About password user authentication\n',
        'PasswordAuthentication no\n',
        '\n',
        '# About public-key user authentication\n',
        'AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/user_authorized_keys/%u\n',
        '\n',
        '# If you have access to any host listed in /etc/ssh/shosts.equiv and\n',
        '# /etc/ssh/ssh_known_hosts, then you can log in this machine directly\n',
        '# using host-based user authentication\n',
        'IgnoreUserKnownHosts yes\n',
        'HostbasedAuthentication yes\n',
        'HostbasedUsesNameFromPacketOnly yes\n',
    ]
    return ''.join(lines).encode()


def put_file(filename, content):
    with open(filename + '.swap', 'wb') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.rename(filename + '.swap', filename)


##############################################################################


def read_fcl_json(filename):
    import json
    import re
    NAME = 'name'           # host/user, name
    KEYS = 'public-keys'    # host/user, public keys
    PRIP = 'private-ip'     # host, null if this machine is not in 302
    PUBA = 'public-ip-port' # host, public tcp port for ssh connection
    NUID = 'id'             # user, numeric uid
    SUDO = 'permit-sudo'    # user, sudo permission
    RE_PUBKEY = (
        '^ssh-ed25519 [A-Za-z0-9+/]{68}$|'
        '^ecdsa-sha2-nistp256 [A-Za-z0-9+/]{139}=$|'
        '^ssh-rsa [A-Za-z0-9+/=]{372,}$')
    ################################################################
    def is_good_hosts_and_users(dd):
        return (type(dd) is dict
            and dd.keys() >= {'hosts', 'users'}
            and is_good_hosts(dd['hosts'])
            and is_good_users(dd['users']))
    def is_good_hosts(hh):
        return (type(hh) is list
            and all(is_good_host(h) for h in hh)
            and contains_no_duplicates(h[NAME] for h in hh)
            and contains_no_duplicates(h[PRIP] for h in hh if h[PRIP])
            and contains_no_duplicates(h[PUBA] for h in hh))
    def is_good_users(uu):
        return (type(uu) is list
            and all(is_good_user(u) for u in uu)
            and contains_no_duplicates(u[NUID] for u in uu)
            and contains_no_duplicates(u[NAME] for u in uu)
            and any(u[SUDO] and u[KEYS] for u in uu))
    def contains_no_duplicates(it):
        vals = list(it)
        return len(vals) == len(set(vals))
    def is_good_host(h):
        return (type(h) is dict and h.keys() >= {NAME, PRIP, PUBA, KEYS}
            and type(h[NAME]) is str
            and type(h[PRIP]) in {str, type(None)}
            and type(h[PUBA]) is str
            and type(h[KEYS]) is list and all(type(k) is str for k in h[KEYS])
            and re.fullmatch('^[a-z][a-z0-9]{1,30}$', h[NAME])
            and is_good_private_ip_address(h[PRIP])
            and is_good_public_ip_address_and_port(h[PUBA])
            and all(re.fullmatch(RE_PUBKEY, k) for k in h[KEYS]))
    def is_good_user(u):
        return (type(u) is dict and u.keys() >= {NUID, NAME, KEYS, SUDO}
            and type(u[NUID]) is int
            and type(u[NAME]) is str
            and type(u[SUDO]) is bool
            and type(u[KEYS]) is list and all(type(k) is str for k in u[KEYS])
            and 10000 <= u[NUID] <= 19999
            and re.fullmatch('^[a-z][a-z0-9]{1,30}$', u[NAME])
            and all(re.fullmatch(RE_PUBKEY, k) for k in u[KEYS]))
    def is_good_private_ip_address(addr):
        PAT = '^10\.3\.2\.([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])$'
        return addr is None or re.fullmatch(PAT, addr)
    def is_good_public_ip_address_and_port(ss):
        PAT = (
            '^'
            '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
            '\.'
            '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
            '\.'
            '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
            '\.'
            '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
            ':'
            '([0-9]|[1-9][0-9]{1,4})'
            '$')
        return re.fullmatch(PAT, ss) and int(ss.split(':')[1]) < 65536
    ################################################################
    with open(filename, 'rb') as f:
        raw_bytes = f.read()
    try:
        raw_str = raw_bytes.decode()
        hosts_and_users = json.loads(raw_str)
        assert is_good_hosts_and_users(hosts_and_users)
        for h in hosts_and_users['hosts']:
            h['public-keys'].sort(key=(
                lambda s:
                    ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa']
                    .index(s.split(' ')[0])
            ))
        return hosts_and_users
    except:
        pass
    raise ValueError('the content of {} is invalid'.format(filename))


##############################################################################


if __name__ == '__main__':
    main(sys.argv)
