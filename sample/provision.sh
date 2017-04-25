#!/bin/bash

#
# this script should exit with 0 status under normal conditions
#
# - avoid unnecessary provisioning process unless --force
# - check user id is 0 (run as root or run with sudo)
# - check this is x64 Ubuntu 16.04
# - check internet connectivity
# - patch timezone setting to UTC+8 (Asia/Taipei)
# - patch /etc/apt/sources.list
# - install and update some software packages
# - patch /etc/ssh/sshd_config
#       no reverse DNS
#       /ssh_authorized_keys/%u is also an AuthorizedKeysFile
#       no password except pssh group
# - add a group named user (gid=10000) if it does not exist yet
# - add a group named pssh (gid=10001) if it does not exist yet
# - add a group named admn (gid=19999) if it does not exist yet
# - put a file /etc/sudoers.d/admn-passwordless-sudo with content "%admn ALL=(ALL:ALL) NOPASSWD: ALL"
# - put a file /usr/local/sbin/fcl-update-users
# - put a file /usr/local/sbin/_fcl_update_users.py
# - create directory /ssh_authorized_keys/
# - create directory /fcl_cluster_management/
#

##############################################################################

set -e
trap '>&2 echo Error: nonzero exit status at line $LINENO in $BASH_SOURCE' ERR

# for more information about the `set` and `trap` builtins, see [1] and [2]
# [1]: https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html#The-Set-Builtin
# [2]: https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html#index-trap

##############################################################################

if [[ -d /fcl_cluster_management && $1 != --force ]]
then
    >&2 echo Error: it seems that this machine is already provisioned
    >&2 echo you can add --force to repeat the provisioning process
    exit 1
fi

##############################################################################

[[ $( id -u ) == 0 ]] || false
[[ $( uname -m ) == x86_64 ]] || false
grep -q '^Ubuntu 16.04' /etc/issue

##############################################################################

curl --silent --show-error --connect-timeout 3 --max-time 5 http://tw.archive.ubuntu.com/ubuntu/ > /dev/null
curl --silent --show-error --connect-timeout 3 --max-time 5 http://security.ubuntu.com/ubuntu/ > /dev/null
curl --silent --show-error --connect-timeout 3 --max-time 5 https://www.google.com.tw/ > /dev/null

##############################################################################

timedatectl set-timezone Asia/Taipei

##############################################################################

tee /etc/apt/sources.list > /dev/null << 'END'
deb http://tw.archive.ubuntu.com/ubuntu/ xenial           main restricted universe multiverse
deb http://tw.archive.ubuntu.com/ubuntu/ xenial-backports main restricted universe multiverse
deb http://tw.archive.ubuntu.com/ubuntu/ xenial-updates   main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu    xenial-security  main restricted universe multiverse
END

##############################################################################

# XXX temprarily commented out

# systemctl stop apt-daily.service
# apt-get update
# tasksel install standard openssh-server
# apt-get -y dist-upgrade
# apt-get -y autoremove

##############################################################################

tee /etc/ssh/sshd_config > /dev/null << 'END'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin prohibit-password
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes

UseDNS no
AuthorizedKeysFile /ssh_authorized_keys/%u .ssh/authorized_keys .ssh/authorized_keys2
PasswordAuthentication no
Match Group pssh
    PasswordAuthentication yes
END

service ssh restart

##############################################################################

A=$( getent group | cut -d: -f1,3 | grep ^user:       | wc -l )
B=$( getent group | cut -d: -f1,3 | grep      :10000$ | wc -l )
C=$( getent group | cut -d: -f1,3 | grep ^user:10000$ | wc -l )

[[ ( $A == 0 && $B == 0 && $C == 0 ) || ( $A == 1 && $B == 1 && $C == 1 ) ]] || false

if [[ $C == 0 ]]
then
    groupadd --gid 10000 user
fi

##############################################################################

A=$( getent group | cut -d: -f1,3 | grep ^pssh:       | wc -l )
B=$( getent group | cut -d: -f1,3 | grep      :10001$ | wc -l )
C=$( getent group | cut -d: -f1,3 | grep ^pssh:10001$ | wc -l )

[[ ( $A == 0 && $B == 0 && $C == 0 ) || ( $A == 1 && $B == 1 && $C == 1 ) ]] || false

if [[ $C == 0 ]]
then
    groupadd --gid 10001 pssh
fi

##############################################################################

A=$( getent group | cut -d: -f1,3 | grep ^admn:       | wc -l )
B=$( getent group | cut -d: -f1,3 | grep      :19999$ | wc -l )
C=$( getent group | cut -d: -f1,3 | grep ^admn:19999$ | wc -l )

[[ ( $A == 0 && $B == 0 && $C == 0 ) || ( $A == 1 && $B == 1 && $C == 1 ) ]] || false

if [[ $C == 0 ]]
then
    groupadd --gid 19999 admn
fi

##############################################################################

touch      /etc/sudoers.d/admn-passwordless-sudo
chmod 0440 /etc/sudoers.d/admn-passwordless-sudo
chown 0:0  /etc/sudoers.d/admn-passwordless-sudo

tee /etc/sudoers.d/admn-passwordless-sudo > /dev/null << 'END'
%admn ALL=(ALL:ALL) NOPASSWD: ALL
END

##############################################################################

tee /usr/local/sbin/fcl-update-users > /dev/null << 'END'
#!/bin/bash
exec /usr/bin/sudo /usr/bin/python3 /usr/local/sbin/_fcl_update_users.py "$@"
END

chown 0:19999 /usr/local/sbin/fcl-update-users
chmod 0750    /usr/local/sbin/fcl-update-users

##############################################################################

tee /usr/local/sbin/_fcl_update_users.py > /dev/null << 'END'
#!/usr/bin/python3

import json
import os
import re
import sys

from collections import namedtuple
from contextlib import contextmanager
from subprocess import PIPE
from subprocess import Popen


##############################################################################


CmdExecResult = namedtuple('CmdExecResult', ['stdout', 'stderr', 'returncode'])


def run_subprocess(command, stdin=None):
    assert type(command) is tuple and all(type(s) is str for s in command)
    assert type(stdin) in {str, bytes, type(None)}
    proc = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = proc.communicate(stdin.encode() if type(stdin) is str else stdin)
    return CmdExecResult(stdout, stderr, proc.returncode)


def system(command, stdin=None):
    return run_subprocess(('sh', '-c', command), stdin=stdin)


##############################################################################


def download_from_url(url):
    command = (
        'curl',
        '--connect-timeout', '3',
        '--max-time', '10',
        '--location',
        '--output', '-',
        url)
    result = run_subprocess(command)
    if result.returncode != 0:
        print('Error: fail to download "%s"' % url, file=sys.stderr)
        sys.exit(1)
    return result.stdout


##############################################################################


@contextmanager
def lock_file(path):
    f = open(path, 'bx')
    f.write(('%d\n' % os.getpid()).encode())
    f.flush()
    try:
        yield
    finally:
        f.close()
        os.remove(path)


##############################################################################

def is_valid_accounts_array(x):
    return (type(x) is list
        and all(is_valid_account_object(e) for e in x)
        and all_elements_are_unique(e['id'] for e in x)
        and all_elements_are_unique(e['account'] for e in x))


def is_valid_account_object(x):
    return (type(x) is dict
        and set(x.keys()) <= {'account', 'id', 'permitsudo', 'pubkeys', 'pwh'}
        and is_valid_account_property(x['account'])
        and is_valid_id_property(x['id'])
        and is_valid_permitsudo_property(x['permitsudo'])
        and is_valid_pubkeys_property(x['pubkeys'])
        and is_valid_pwh_property(x['pwh']))


def all_elements_are_unique(it):
    vals = list(it)
    return len(set(vals)) == len(vals)


def is_valid_account_property(x):
    return type(x) is str and None is not re.match('^[a-z][a-z0-9]{1,30}$', x)


def is_valid_id_property(x):
    return type(x) is int and 10000 <= x <= 19999


def is_valid_permitsudo_property(x):
    return type(x) is bool


def is_valid_pubkeys_property(x):
    return (type(x) is list
        and all(is_valid_pubkey_str(e) for e in x)
        and all_elements_are_unique(x))


def is_valid_pubkey_str(x):
    pat_ecdsa = '^ecdsa-sha2-nistp256 [A-Za-z0-9+/]{139}=$'
    pat_ed25519 = '^ssh-ed25519 [A-Za-z0-9+/]{68}$'
    pat_rsa = ('^ssh-rsa [A-Za-z0-9+/]{372}([A-Za-z0-9+/]{4})*'
        '([A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$')
    patterns = [pat_ecdsa, pat_ed25519, pat_rsa]
    return type(x) is str and any(re.match(p, x) for p in patterns)


def is_valid_pwh_property(x):
    return type(x) is str and (x == '*' or x.startswith('$6$'))


##############################################################################


def get_accounts_json_url():
    args = sys.argv[1:]
    if len(args) != 1:
        print('Error: you must provide a URL that yields accounts.json', file=sys.stderr)
        sys.exit(1)
    return args[0]


def validate_accounts_json_raw(accounts_json_raw):
    try:
        accounts_json_str = accounts_json_raw.decode()
        accounts = json.loads(accounts_json_str)
    except:
        print(repr(accounts_json_raw))
        print('Error: invalid JSON format', file=sys.stderr)
        sys.exit(1)
    if not is_valid_accounts_array(accounts):
        print('Error: invalid accounts.json format', file=sys.stderr)
        sys.exit(1)
    return accounts


def get_passwd_db():
    return [line.split(':') for line in system('getent passwd').stdout.decode().split('\n')[:-1]]


def apply_state(accounts):
    passwd_db = get_passwd_db()
    passwd_uid_gid_list = [(int(entry[2]), int(entry[3])) for entry in passwd_db]
    passwd_name_uid_list = [(entry[0], int(entry[2])) for entry in passwd_db if int(entry[3]) == 10000]

    uid_gid_is_good = lambda uid, gid: (
        not (10000 <= uid <= 19999 or  gid == 10000)
        or  (10000 <= uid <= 19999 and gid == 10000) )

    name_uid_is_good = lambda name, uid: (
        any(name == a['account'] and uid == a['id'] for a in accounts)
    )

    # 檢查是否有些帳號不合法，誤用了我們的 uid, gid 的 10000~19999 範圍
    if not all(uid_gid_is_good(uid, gid) for uid, gid in passwd_uid_gid_list):
        print('Error: there are some bad entries in /etc/passwd', file=sys.stderr)
        sys.exit(1)

    # 檢查我們的 accounts.json 是否有漏網之魚（我們原則上從來不「刪」帳號）
    if not all(name_uid_is_good(name, uid) for name, uid in passwd_name_uid_list):
        print('Error: there are some gid=10000 entries in /etc/passwd that is not in your accounts.json file', file=sys.stderr)
        sys.exit(1)

    # 有些帳號需要建立
    for a in accounts:
        if (a['account'], a['id']) not in passwd_name_uid_list:
            assert 0 == system('useradd --create-home --shell /bin/bash --gid 10000 --uid %d %s' % (a['id'], a['account'])).returncode

    # pssh 群組成員可以密碼遠端登入
    pssh_members_str = ','.join(a['account'] for a in accounts if a['pwh'] != '*')
    assert 0 == system('gpasswd --members "%s" pssh' % pssh_members_str).returncode

    # admn 群組成員可以免密碼使用 sudo 指令
    admn_members_str = ','.join(a['account'] for a in accounts if a['permitsudo'])
    assert 0 == system('gpasswd --members "%s" admn' % admn_members_str).returncode

    for a in accounts:
        assert 0 == system('usermod --password "%s" %s' % (a['pwh'], a['account'])).returncode

    for a in accounts:
        assert 0 == system('tee /ssh_authorized_keys/%s > /dev/null' % a['account'], stdin=(
            '' if len(a['pubkeys']) == 0 else '\n'.join(a['pubkeys'] + [''])
        )).returncode


def main():
    accounts_json_url = get_accounts_json_url()
    accounts_json_raw = download_from_url(accounts_json_url)
    accounts = validate_accounts_json_raw(accounts_json_raw)
    apply_state(accounts)


if __name__ == '__main__':
    if os.getuid() != 0:
        print('Error: %s should be run as root' % sys.argv[0], file=sys.stderr)
        sys.exit(1)
    with lock_file('/fcl_cluster_management_lock'):
        main()
END

chown 0:0  /usr/local/sbin/_fcl_update_users.py
chmod 0700 /usr/local/sbin/_fcl_update_users.py

##############################################################################

mkdir -p   /ssh_authorized_keys
chown 0:0  /ssh_authorized_keys
chmod 0755 /ssh_authorized_keys

##############################################################################

mkdir -p   /fcl_cluster_management
chown 0:0  /fcl_cluster_management
chmod 0700 /fcl_cluster_management

##############################################################################

echo 'Provisioning process finished!'
echo 'Now you should run `sudo fcl-update-users {{accounts_json_url}} command` to setup user accounts on this machine'
