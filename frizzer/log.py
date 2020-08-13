# This is a temporary replacement for pwntools' log command
# TODO: Add sophisticated logging + nice ui output etc.

import sys

# colors:
COLOR_NC     ='\033[0m'  # No Color
WHITE        ='\033[37m'
BLACK        ='\033[30m'
BLUE         ='\033[34m'
GREEN        ='\033[32m'
CYAN         ='\033[36m'
RED          ='\033[31m'
PURPLE       ='\033[35m'
BROWN        ='\033[33m'
YELLOW       ='\033[33m'
GRAY         ='\033[30m'

CLEAR_LINE   ='\033[K'

update_ongoing = False
logfile        = None
use_color      = True

# debug = 3   info = 2   warn = 1
log_level = 2 

def add_color(msg, color):
    if use_color:
        return color + msg + COLOR_NC
    else:
        return msg

def writeLine(msg, do_update_line=False):
    global update_ongoing, logfile
    if not do_update_line:
        # if we are not called from update() and are currently in update_ongoing
        # then stop update_ongoing by going to the next line:
        if update_ongoing:
            sys.stdout.write("\n")
            update_ongoing = False
        sys.stdout.write(msg + "\n")
    else:
        sys.stdout.write(msg)

    if logfile != None:
        msg = msg + "\n"
        for i in ["\r",COLOR_NC,WHITE,BLACK,BLUE,GREEN,CYAN,RED,PURPLE,BROWN,YELLOW,GRAY,CLEAR_LINE]:
            msg = msg.replace(i,"")
        logfile.write(msg.encode("ascii"))

def update(msg):
    global update_ongoing, log_level
    if log_level >= 2:
        update_ongoing = True
        clear_line_seq = CLEAR_LINE if use_color else ""
        msg = "\r"+clear_line_seq+"[" + add_color("*",YELLOW) + "] " + msg
        writeLine(msg, do_update_line=True)

def finish_update(msg):
    global update_ongoing, log_level
    if log_level >= 2:
        update_ongoing = False
        writeLine("\r"+CLEAR_LINE+"[" + add_color("*",GREEN) + "] " + msg)

def debug(msg):
    global log_level
    if log_level >= 3:
        writeLine("[" + add_color("D",GRAY) + "] " + msg)

def info(msg):
    global log_level
    if log_level >= 2:
        writeLine("[" + add_color("+",BLUE) + "] " + msg)

def warn(msg):
    global log_level
    if log_level >= 1:
        writeLine("[" + add_color("!",RED) + "] " + msg)

