#!/usr/bin/env python3


import os
import subprocess
import socket
from datetime import datetime, timedelta

BASE_DIR = "/home/sre-archives"
CURRENT_NAME = "current"
OFFSET = -1
EXPORTS_FILE = "/etc/exports.d/sre-archives.exports"

# The list of machines names. Here:
# a1, a2,... , a16, b1, b2, ..., b16
MACHINES = [f"a{i}" for i in range(1, 17)] + [f"b{i}" for i in range(1, 17)]


def get_target_name(base_dir):
    target_date = datetime.now() + timedelta(days=OFFSET)
    target0 = target_date.strftime("%Y-%m-%d")
    target = target0
    counter = 1

    while os.path.exists(os.path.join(base_dir, target)):
        target = f"{target0}_{counter}"
        counter += 1

    return target


def main():
    actuel_path = os.path.join(BASE_DIR, CURRENT_NAME)
    if os.path.isdir(actuel_path):
        target_name = get_target_name(BASE_DIR)
        dst_path = os.path.join(BASE_DIR, target_name)
        os.rename(actuel_path, dst_path)
        os.system(f"rmdir --ignore-fail-on-non-empty {dst_path}/*")
        print(f"'{CURRENT_NAME}' -> '{target_name}'")
    else:
        print(f"Error: '{CURRENT_NAME}' directory not found in {BASE_DIR}")
    maj_actuel(actuel_path)


def maj_actuel(main_dir: str):
    machines = MACHINES
    f = open(EXPORTS_FILE, 'w')
    for machine in machines:
        ip = socket.gethostbyname(machine)
        f.write(f"{main_dir}/{machine} {ip}(rw,async,no_root_squash,no_subtree_check)\n")
    f.close()

    for m in machines:
        os.system(f"mkdir -p {main_dir}/{m}")
    os.system(f"chown -R sre:sre {main_dir}")
    os.system("systemctl reload nfs-kernel-server")


if __name__ == "__main__":
    main()
