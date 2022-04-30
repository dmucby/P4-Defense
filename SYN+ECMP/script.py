#! /usr/bin/python3

"""

"""

import time,os
import random

def main(cmd):
    while True:
        inc = random.randint(10,20)
        os.system(cmd)
        time.sleep(inc)


if __name__ == '__main__':
    cmd = "python controller.py"
    main(cmd)
