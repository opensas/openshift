import sys
import subprocess
from optparse import OptionParser

MODULE = 'openshift'

# Commands that are specific to your module
COMMANDS = []
for command in ["hello", "chk", "info"]:
    COMMANDS.append("openshift:%s" % command)
    COMMANDS.append("rhc:%s" % command)

class OpenshiftOptionParser(OptionParser):
    def error(self, msg):
        pass

def execute(**kargs):
    command = kargs.get("command")
    app = kargs.get("app")
    args = kargs.get("args")
    env = kargs.get("env")

    command = command[command.index(":")+1:]

    parser = OpenshiftOptionParser()
    parser.add_option("-a", "--app", dest="app", help="Application name  (alphanumeric) (required)")
    parser.add_option("-l", "--rhlogin", dest="rhlogin", help="Red Hat login (RHN or OpenShift login with OpenShift Express access)")
    parser.add_option("-p", "--password", dest="password", help="RHLogin password  (optional, will prompt)")
    parser.add_option("-d", "--debug", dest="debug", help="Print Debug info")
    parser.add_option("", "--timeout", dest="timeout", help="Timeout, in seconds, for connection")
    options, args = parser.parse_args(args)

    app.check()

    print options

    sys.exit()

    if command == "hello":
        print "~ Hello"

    if command == "chk":
        openshift_check()

    if command == "info":
        openshift_info(options)

# This will be executed before any command (new, run...)
def before(**kargs):
    command = kargs.get("command")
    app = kargs.get("app")
    args = kargs.get("args")
    env = kargs.get("env")


# This will be executed after any command (new, run...)
def after(**kargs):
    command = kargs.get("command")
    app = kargs.get("app")
    args = kargs.get("args")
    env = kargs.get("env")

    if command == "new":
        pass

def openshift_check():
    check_git()

def check_git():
    git_cmd = ["git", "version"]
    try:
        result = subprocess.call(git_cmd)
        if not result == 0:
            print "~"
            print "~ Failed to execute git, check that git is installed."
            print "~"
            sys.exit(-1)

    except OSError:
        print "~"
        print "~ Failed to execute git, check that git is installed."
        print "~"
        sys.exit(-1)


def openshift_info(options):
    info_cmd = ["rhc-user-info", "--apps"]

    if options.rhlogin == None:
        print "~"
        print "~ You must provide rhlogin parameter."
        print "~"
        sys.exit(-1)

    if options.password == None:
        print "~"
        print "~ You must provide rhlogin parameter."
        print "~"
        sys.exit(-1)


    #for item in ["rhlogin", "password", "debug", "timeout"]:
    #    if eval('options.%s' % item) != None:
    #        info_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

    try:

        print info_cmd
        result = subprocess.call(info_cmd)
        if not result == 0:
            print "~"
            print "~ Failed to execute rhc-user-info, check that rhc-user-info is installed."
            print "~"
            sys.exit(-1)

    except OSError:
        print "~"
        print "~ Failed to execute rhc-user-info, check that rhc-user-info is installed."
        print "~"
        sys.exit(-1)


