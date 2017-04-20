# FCL Computer Cluster

This repository will contain public information about our computer cluster.
Public keys, IPv4 addresses, TCP ports, usernames, user ids...

Directory structure will look like this:

    /
    /build/
    /build/hosts.js
    /build/hosts.json
    /build/users.js
    /build/users.json
    /compile.py
    /index.html
    /src/
    /src/hosts/
    /src/hosts/angel
    /src/hosts/behemoth
    /src/hosts/colossus
    /src/users/
    /src/users/alice
    /src/users/bob
    /src/users/carol

Docs should be organized as another git repository.


TODO
    write scripts to do
        1. validate source files in src/
        2. normalize source files in src/
        3. compile build/{hosts,users}.js{,on}
