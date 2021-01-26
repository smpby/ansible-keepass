# Ansible KeePass Lookup Plugin

> The plugin allows to read data from KeePass file (no way to change it)

The plugin opens a UNIX socket, inside which a KeePass file is decrypted. 
For performance reasons, decryption occurs only once at socket startup, 
and the KeePass file remains decrypted as long as the socket is open. 
The KeePass password is sent directly from the plugin to the opened socket.
The UNIX socket file is stored in a temporary folder according to OS.


## Installation

Requirements: `python3`, `pykeepass`

    pip install pykeepass --user
    ansible-galaxy install git+https://github.com/viczem/ansible-keepass.git,main


## Variables

- `keepass_dbx` - path to KeePass file
- `keepass_psw` - password
- `keepass_key` - *Optional*. Path to keyfile
- `keepass_ttl` - *Optional*. Socket TTL (will be closed automatically when not used). 
Default 60 seconds.


## Usage

See [examples](/examples) folder.

`ansible-doc -t lookup keepass` to get description of the plugin

For security reasons, do not store KeePass passwords in plain text. 
Use `ansible-vault encrypt_string` to encrypt it and use it like below

    # file: group_vars/all

    keepass_dbx: "~/.keepass/database.kdbx"
    keepass_psw: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...encrypted password...
