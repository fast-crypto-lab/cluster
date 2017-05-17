For all FCL members

    To create an account, you provide the following info to admin

        1.  identity proof
        2.  English full name
        3.  email address
        4.  one or more username candidates
        5.  one or more SSH public keys
        6.  whether you need sudo privilege

    To update your account, you provide

        1.  identity proof
        2.  what you want to change

    You can update your ~/.ssh/config to include our cluster host
    declarations:

        https://fast-crypto-lab.github.io/cluster/cluster-info/ssh_config.txt

    You can update your ~/.ssh/known_hosts to include our cluster host public
    keys:

        https://fast-crypto-lab.github.io/cluster/cluster-info/ssh_known_hosts.txt

    For more information check ssh(1) and ssh_config(5) manual pages.

    With great power comes great responsibility.  If you are granted sudo
    privilege, you should be careful not to destroy the cluster...


------------------------------------------------------------------------------


For administrators

    To add a new account

        1.  verify the authenticity of an account creation request
        2.  reject bad request (unknown requester, missing info, username in use)

        3.  open the Google spreadsheet containing all account information
        4.  append a new row with proper (username, uid, fullname, email) value

        5.  enter the git repository
        6.  vim ./cluster-info/users/{newuid}-{newusername}
        7.  ./cluster-info/compile
        8.  git add ./cluster-info/
        9.  git commit
        10. git push
        11. ./broadcast

    To update sudo privilege and public keys of an existing account

        1.  enter the git repository
        2.  vim ./cluster-info/users/{newuid}-{newusername}
        3.  ./cluster-info/compile
        4.  git add ./cluster-info/
        5.  git commit
        6.  git push
        7.  ./broadcast

    To update account information (email address)

        1.  open the Google spreadsheet containing all account information
        2.  update an existing row with proper value

    To add a new host

        1.  make sure sshd on the machine does have a public TCP port
        2.  run ./bootstrap on the new host

                curl -fsL https://fast-crypto-lab.github.io/cluster/bootstrap | sudo bash

        3.  vim ./cluster-info/hosts/{newhostname}
        4.  ./cluster-info/compile
        5.  git add ./cluster-info/
        6.  git commit
        7.  git push
        8.  ./broadcast


------------------------------------------------------------------------------


For each server, you should put a host file in the hosts/ directory

    A host file should look like this:

            private-ip 10.3.2.???
            public-ip-port ???.???.???.???:????
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHjJcnsuBYh...
            ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHA...
            ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpybp47VL...

    If the host does not have an 10.3.2.* address, the private-ip line should be

            private-ip none

    The filename of a host file is "$HOSTNAME"



For each cluster user, you should put a user file in the users/ directory

    A user file should look like this:

            permit-sudo no
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOQrdUdgaIc...

    If the user is permitted to run sudo, the permit-sudo line should be

            permit-sudo yes

    The filename of a user file is "$UID-$USER"
