#!/usr/bin/env python3
# exetests
# -------------------------------------------------
# read the EXETESTS environment variable which contains lines of the format timeout:cmd
#  - timeout is the maximal execution time in seconds
#  - cmd is a shell command
import datetime
import sys
import subprocess
import os
import uuid

exetests_env_name = "EXETESTS"
exetests_separator = '@@@'

exetests = os.getenv(exetests_env_name)
if exetests is None:
    print(f"exetests: no {exetests_env_name} variable", file=sys.stderr)
    sys.exit(1)
cmds=os.getenv(exetests_env_name).split(exetests_separator)
if len(cmds) == 0:
    print(f"exetests: empty {exetests_env_name} variable", file=sys.stderr)
    sys.exit(1)
os.unsetenv(exetests_env_name)

separator= f"---{uuid.uuid4().hex}---"

start = True
for ligne in cmds:
    print(separator, flush=True)
    parts = ligne.strip().split(":", 1)
    if len(parts) < 2:
        print("exetests: illegal input", file=sys.stderr, flush=True)
        sys.exit(1)
    timeout=int(parts[0])
    cmd=parts[1]
    print(f"{ligne}\n{datetime.datetime.now().isoformat()}", flush=True)
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True,
            env={
                **os.environ,
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            },
            timeout=timeout,
        )
        print(f"\n{separator}\n{datetime.datetime.now().isoformat()}\n{proc.returncode}", flush=True)
    except subprocess.TimeoutExpired as te:
        if te.output:
            print(te.output)
        print(f"\n{separator}\n{datetime.datetime.now().isoformat()}\n-1", flush=True)
    except Exception as e:
        print(f"\n{separator}\n{datetime.datetime.now().isoformat()}\nERROR {e}", flush=True)

