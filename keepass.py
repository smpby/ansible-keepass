__metaclass__ = type

import os
import json
import socket
import tempfile
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

import time
import subprocess
import sys
import argparse
import getpass
import hashlib
import traceback
import stat


DOCUMENTATION = """
    lookup: keepass
    author: Victor Zemtsov <viczem.dev@gmail.com>
    version_added: '0.3'
    short_description: Fetching data from KeePass
    description:
        - Plugin allows to read data from KeePass file (no way to change it).
        - This lookup returns a value of a property of a KeePass entry 
        - which fetched by given path
    options:
      _terms:
        description: 
          - first is a path to KeePass entry
          - second is a property name of the entry, e.g. username or password
        required: True
    notes:
      - https://github.com/viczem/ansible-keepass
    
    examples:
      - "{{ lookup('keepass', 'path/to/entry', 'password') }}"
"""


display = Display()


class LookupModule(LookupBase):
    keepass = None

    def _var(self, var_value):
        return self._templar.template(var_value, fail_on_undefined=True)

    def run(self, terms, variables=None, **kwargs):
        if not terms or len(terms) < 2:
            raise AnsibleError("KeePass: number of arguments is less than 2")
        if not all(isinstance(_, str) for _ in terms):
            raise AnsibleError("KeePass: invalid argument type, all must be string")

        if variables is not None:
            self._templar.available_variables = variables
        variables_ = getattr(self._templar, "_available_variables", {})

        # Check keepass database file (required)
        var_dbx = self._var(variables_.get("keepass_dbx", ""))
        if not var_dbx:
            raise AnsibleError("KeePass: 'keepass_dbx' is not set")
        var_dbx = os.path.realpath(os.path.expanduser(os.path.expandvars(var_dbx)))
        if not os.path.isfile(var_dbx):
            raise AnsibleError("KeePass: '%s' is not found" % var_dbx)

        # Check key file (optional)
        var_key = self._var(variables_.get("keepass_key", ""))
        if var_key:
            var_key = os.path.realpath(os.path.expanduser(os.path.expandvars(var_key)))
            if not os.path.isfile(var_key):
                raise AnsibleError("KeePass: '%s' is not found" % var_key)

        # Check password (required)
        var_psw = self._var(variables_.get("keepass_psw", ""))
        if not var_psw:
            raise AnsibleError("KeePass: 'keepass_psw' is not set")

        # TTL of keepass socket (optional, default: 60 seconds)
        var_ttl = self._var(str(variables_.get("keepass_ttl", 60)))

        # UNIX socket path for a dbx (supported multiple dbx)
        tempdir = tempfile.gettempdir()
        if not os.access(tempdir, os.W_OK):
            raise AnsibleError("KeePass: no write permissions to '%s'" % tempdir)
        socket_path = "%s/ansible-keepass-%s.sock" % (
            tempdir,
            hashlib.sha1(("%s%s" % (getpass.getuser(), var_dbx)).encode()).hexdigest(),
        )

        try:
            # If UNIX socket file is not exists then the socket is not running
            stat.S_ISSOCK(os.stat(socket_path).st_mode)
        except FileNotFoundError:
            cmd = [
                "/usr/bin/env",
                "python3",
                os.path.abspath(__file__),
                var_dbx,
                socket_path,
                var_ttl,
            ]
            if var_key:
                cmd.append("--key=%s" % var_key)
            try:
                display.v("KeePass: run socket for %s" % var_dbx)
                subprocess.Popen(cmd)
            except OSError:
                raise AnsibleError(traceback.format_exc())

            attemts = 10
            success = False
            for _ in range(attemts):
                try:
                    display.vvvv("KeePass: test socket connection %s/%s" % (_, attemts))
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(socket_path)
                    # send password to the socket for decrypt keepass dbx
                    display.vvvv("KeePass: send password to '%s'" % socket_path)
                    sock.send(_rq("keepass", "password", str(var_psw)))
                    resp = json.loads(sock.recv(1024).decode())
                    if (
                        resp["status"] == 1
                        and resp["cmd"] == "keepass"
                        and resp["body"] == "password"
                    ):
                        sock.close()
                        raise AnsibleError("KeePass: wrong dbx password")
                    sock.close()
                    success = True
                    break
                except FileNotFoundError:
                    # wait until the above command open the socket
                    time.sleep(1)

            if not success:
                raise AnsibleError("KeePass: socket connection failed for %s" % var_dbx)
            display.v("KeePass: open socket for %s -> %s" % (var_dbx, socket_path))
        # Fetching data from the keepass socket
        return self._fetch(socket_path, terms)

    def _fetch(self, kp_soc, terms):
        display.vvvv("KeePass: connect to '%s'" % kp_soc)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            sock.connect(kp_soc)
        except FileNotFoundError:
            raise AnsibleError("KeePass: '%s' is not found" % kp_soc)

        display.vv("KeePass: fetch '%s': '%s'" % (terms[0], terms[1]))
        sock.send(_rq("fetch", *terms))
        try:
            resp = json.loads(sock.recv(1024).decode())
            if resp["status"] > 0:
                raise AnsibleError(resp["body"])
            if resp["cmd"] == "fetch":
                return [resp["body"]]
            raise AnsibleError("KeePass: '%s' is unknown command" % resp["cmd"])
        except json.JSONDecodeError as e:
            raise AnsibleError(str(e))
        finally:
            sock.close()
            display.vvvv("KeePass: disconnect from '%s'", kp_soc)


def _keepass_socket(kdbx, kdbx_key, sock_path, ttl=60):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.bind(sock_path)
            s.listen(1)
            s.settimeout(ttl)
            os.chmod(sock_path, 0o600)
            kp = None

            while True:
                conn, addr = s.accept()
                with conn:
                    conn.settimeout(ttl)
                    while True:
                        data = conn.recv(1024).decode()
                        if not data:
                            break

                        rq = json.loads(data)
                        if not isinstance(rq, dict):
                            print("wrong request format")
                            raise ValueError("wrong request format")

                        if rq.keys() != {"cmd", "arg"}:
                            print("wrong request props")
                            raise ValueError("wrong request props")

                        if kp is None:
                            if rq["cmd"] == "keepass" and rq["arg"][0] == "password":
                                kp = PyKeePass(kdbx, rq["arg"][1], kdbx_key)
                                conn.send(_resp(0, "keepass", "password"))
                            else:
                                conn.send(_resp(1, "keepass", "password"))
                            continue

                        if rq["cmd"] == "fetch":
                            path = rq["arg"][0].strip("/")
                            attr = rq["arg"][1]
                            entr = kp.find_entries_by_path(path, first=True)

                            if entr is None:
                                conn.send(
                                    _resp(1, "fetch", "path %s is not found" % path)
                                )
                                continue

                            if not hasattr(entr, attr):
                                conn.send(
                                    _resp(1, "fetch", "attr %s is not found" % attr)
                                )
                                continue

                            conn.send(_resp(0, "fetch", getattr(entr, attr)))
    except CredentialsError:
        print("%s failed to decrypt" % kdbx)
        sys.exit(1)
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)
    except json.JSONDecodeError as e:
        print("JSONDecode: %s" % e)
        sys.exit(1)
    except ValueError as e:
        print(str(e))
        sys.exit(1)
    except (KeyboardInterrupt, socket.timeout):
        pass
    finally:
        print("Close ansible-keepass socket")
        if os.path.exists(sock_path):
            os.remove(sock_path)


def _rq(cmd, *arg):
    """Request to keepass socket

    :param str cmd: Command name
    :param arg: Arguments
    :return: JSON
    """
    return json.dumps({"cmd": cmd, "arg": arg}).encode()


def _resp(status, cmd, body=""):
    """Response from keepass socket

    :param int status: == 0 - no error; > 0 - an error
    :param str cmd: Command name
    :param body: A data from keepass
    :return: JSON
    """
    return json.dumps({"status": status, "cmd": cmd, "body": body}).encode()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("kdbx", type=str)
    arg_parser.add_argument("kdbx_sock", type=str)
    arg_parser.add_argument("ttl", type=int, default=60)
    arg_parser.add_argument("--key", type=str, nargs="?", default=None)
    args = arg_parser.parse_args()
    _keepass_socket(args.kdbx, args.key, args.kdbx_sock, args.ttl)
