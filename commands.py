import sys
import subprocess
import re
import os
import shutil
import webbrowser
from datetime import datetime

from optparse import OptionParser

MODULE = 'openshift'

# Commands that are specific to your module
COMMANDS = []
for command in ["hello", "chk", "info", "app", "create", "open", "deploy"]:
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
	parser.add_option("-a", "--app",        default='',     dest="app",         help="Application name  (alphanumeric) (required)")
	parser.add_option("-s", "--subdomain",  default='',     dest="subdomain",   help="Application subdomain, root by default  (alphanumeric) (optional)")
	parser.add_option("-l", "--rhlogin",    default='',     dest="rhlogin",     help="Red Hat login (RHN or OpenShift login with OpenShift Express access)")
	parser.add_option("-p", "--password",   default='',     dest="password",    help="RHLogin password  (optional, will prompt)")
	parser.add_option("-d", "--debug",      default=False,  dest="debug",       action="store_true", help="Print Debug info")
	parser.add_option("", "--timeout",      default='',     dest="timeout",     help="Timeout, in seconds, for connection")
	options, args = parser.parse_args(args)

	if options.app == '': options.app = app.readConf('openshift.application.name')
	if options.app == '': options.app = app.readConf('application.name')

	if options.subdomain == '': options.subdomain = app.readConf('openshift.application.subdomain')

	if options.rhlogin == '': options.rhlogin = app.readConf('openshift.rhlogin')
	if options.rhlogin == '': error_message("You must provide rhlogin parameter using the command line or setting openshift.rhlogin in application.conf file.")

	if options.password == '': options.password = app.readConf('openshift.password')
	if options.password == '': message([\
		"Password not specified. You'll be asked to enter your password", \
		"You can provide it using the command line or setting openshift.password in application.conf file."])

	if options.debug == '': options.debug = app.readConf('openshift.debug')
	if options.debug == '': options.debug = False

	if options.timeout == '': options.timeout = app.readConf('openshift.timeout')
	if options.timeout == '': del options.timeout

	app.check()

	#print options

	if command == "hello": 		print "~ Hello"
	if command == "chk": 		openshift_check(app, options)
	if command == "info": 		openshift_info(options)
	if command == "app": 		openshift_app(options)
	if command == "create": 	create_app(app, options)
	if command == "open": 		open_app(options)
	if command == "deploy": 	deploy_app(app, env, options)

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

def deploy_app(app, env, options):
	openshift_app = check_app(app, options)
	check_local_repo(app, openshift_app, options)

	app_folder = os.path.join(app.path, '.openshift', options.app)
	deploy_folder = os.path.join(app_folder, 'deployments')

	#delete deploy_folder folder to start it all over again
	if os.path.exists(deploy_folder): shutil.rmtree(deploy_folder)

	#could not delete deploy_folder folder
	if os.path.exists(deploy_folder):
		error_message("ERROR - '%s' folder already exists and could not be deleted\nremove it and try again" % odeploy_folder)

	os.mkdir(deploy_folder)
	if not os.path.exists(deploy_folder):
		error_message("ERROR - '%s' deployment folder could not be created" % deploy_folder)

	if options.subdomain == '':
		war_file = 'ROOT.war'
	else:
		war_file = options.subdomain + '.war'

	date = str(datetime.now())
	dodeploy_filename = os.path.join(deploy_folder, war_file + '.dodeploy')
	dodeploy_file = open(dodeploy_filename, 'w')
	dodeploy_file.write(date)
	dodeploy_file.close()

	war_path = os.path.join(deploy_folder, war_file)

	out, err = shellexecute( ['play', 'war', '-o', war_path, '--exclude', '.openshift'], msg="Generating war file", debug=options.debug, output=True)
	if err != '':
		err.insert(0, "ERROR - error generating war file to %s" % war_path)
		error_message(err)

	#add files
	out, err = shellexecute( ['git', 'add', 'deployments'], location=app_folder, msg="Adding deployments folder to index", debug=options.debug, output=True)
	if err != '':
		err.insert(0, "ERROR - error adding deployments folder to index (%s)" % (deploy_folder))
		error_message(err)

	out, err = shellexecute( ['git', 'add', 'deployments'], location=app_folder, msg="Adding deployments folder to index", debug=options.debug, output=True)
	if err != '':
		err.insert(0, "ERROR - error adding deployments folder to index (%s)" % (deploy_folder))
		error_message(err)

	out, err = shellexecute( ['git', 'commit', '-m', '"deployed at ' + date + '"'], location=app_folder, msg="Commiting deployment", debug=options.debug, output=True)
	if err != '':
		err.insert(0, "ERROR - error committing deployments")
		error_message(err)

	out, err = shellexecute( ['git', 'push', 'origin'], location=app_folder, msg="Pushing to origin", debug=options.debug, output=True)
	if err != '':
		err.insert(0, "ERROR - error pushing changes")
		error_message(err)

	message(["app successfully deployed", "issue play rhc:open to see it in action"])

def open_app(options):
	openshift_app = appinfo(options)
	if openshift_app == None:
		message("the application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))
	url = openshift_app.url
	if options.subdomain != '': url = url.rstrip('/') + '/' + options.subdomain.strip('/')
	webbrowser.open(url, new=2)

def openshift_check(app, options):
	check_git(options)
	check_ruby(options)
	check_rhc(options)
	#check_rhc_chk(options)
	check_appname(options.app)
	openshift_app = check_app(app, options)
	check_local_repo(app, openshift_app, options)

def check_git(options):
	out, err = shellexecute(["git", "version"], debug=options.debug)
	if err != '':
		err.insert(0, "ERROR - Failed to execute git, check that git is installed.")
		error_message(err)
	message("OK! - checked git version: %s" % out)

def check_ruby(options):
	out, err = shellexecute(["ruby", "-v"], debug=options.debug)
	if err != '':
		err.insert(0, "ERROR - Failed to execute ruby, check that ruby is installed.")
		error_message(err)
	message("OK! - checked ruby version: %s" % out)

def check_rhc(options):
	out, err = shellexecute(["gem", "list", "rhc"], debug=options.debug)
	if err != '':
		err.insert(0, "ERROR - Failed to execute gem list rhc, check that gem is installed.")
		error_message(err)
	message("OK! - checked rhc version: %s" % out)

def check_rhc_chk(options):
	create_cmd = ["rhc-chk"]

	if options.debug == True: create_cmd.append("-d")

	for item in ["rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			create_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	out, err = shellexecute( create_cmd, output=True, debug=options.debug, msg="Running rhc-chk")
	if err != '':
		err.insert(0, "Failed to execute rhc-chk, check that rhc-chk is installed.")
		error_message(err)

def check_appname(appname):
	if re.match("^[a-zA-Z0-9]+$", appname) == None:
		error_message("ERROR - Invalid application name: '%s'. It should only contain alphanumeric characters" % appname)
	message("OK! - checked application name: %s - OK!" % appname)

def check_app(app, options):
	openshift_app = appinfo(options)
	if openshift_app == None:
		message("the application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))
		answer = raw_input("~ Do you want to create it? [%s] " % "yes")

		answer = answer.strip().lower()
		if answer in ['yes', 'y', '']:
			openshift_app = create_app(app, options)
		else:
			error_message("the application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))

	message("OK! - checked application: %s at %s for user %s!" % (openshift_app.name, openshift_app.url, options.rhlogin))
	return openshift_app

def check_local_repo(app, openshift_app, options):
	openshift_folder = os.path.join(app.path, '.openshift')
	if not os.path.exists(openshift_folder):
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - '%s' folder does not exists, openshift folder is not available" % openshift_folder)

	app_folder = os.path.join(openshift_folder, options.app)
	if not os.path.exists(app_folder):
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - %s folder does not exists, application folder is not available" % openshift_folder)

	git_folder = os.path.join(app_folder, '.git')
	if not os.path.exists(git_folder):
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - '%s' folder does not exists, '%s' does not seem to be a valid git repository" % (git_folder, app_folder) )

	out, err = shellexecute( ['git', 'status'], location=app_folder, debug=options.debug)
	if err != '':
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - folder '%s' exists but does not seem to be a valid git repo" % git_folder )

	out, err = shellexecute( ['git', 'remote', '-v'], location=app_folder, debug=options.debug)
	if err != '':
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - error fetching folder remotes for '%s' git repository" )

	remote_found = False
	remotes = out.splitlines()
	for remote in remotes:
		values = remote.split(None, 2)
		#check if the repo is somewhere listed
		for value in values:
			if value.strip().lower() == openshift_app.repo:
				remote_found = True
				break

	if not remote_found:
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - could not found remote '%s' in '%s' git repo" % (openshift_app.repo, git_folder) )

	message("OK! - folder '%s' exists and seems to be a valid git repo" % git_folder)

def create_app(app, options):

	openshift_folder = os.path.join(app.path, '.openshift')
	app_folder = os.path.join(openshift_folder, options.app)

	#delete openshift folder to start it all over again
	if os.path.exists(openshift_folder): shutil.rmtree(openshift_folder)

	#could not delete openshift folder
	if os.path.exists(openshift_folder):
		error_message("ERROR - '%s' folder already exists and could not be deleted\nremove it and try again" % openshift_folder)

	if not os.path.exists(openshift_folder): os.mkdir(openshift_folder)
	if not os.path.exists(openshift_folder):
		error_message("ERROR - '%s' folder could not be created" % openshift_folder)

	openshift_app = appinfo(options)

	#create openshift application
	if openshift_app == None:
		message("creating a new openshift '%s' application at '%s'" % (options.app, openshift_folder))

		create_cmd = ["rhc-create-app", "--type", 'jbossas-7.0']

		if options.debug == True: create_cmd.append("-d")

		for item in ["app", "rhlogin", "password", "timeout"]:
			if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
				create_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

		out, err = shellexecute( create_cmd, location=openshift_folder, output=True, debug=options.debug, msg="Creating %s application at openshift" % options.app)
		print out
		print err
		if err != '':
			err.insert(0, "Failed to execute rhc-create-app, check that rhc-create-app is installed.")
			error_message(err)

		openshift_app = appinfo(options)
		if openshift_app == None:
			error_message("Failed to create app, check that rhc-create-app is installed.")

		app_folder = os.path.join(openshift_folder, options.app)
		local_repo_remove_default_app(app_folder, options)

		message("Repository at %s successfully created" % app_folder)

	return openshift_app

def create_local_repo(app, openshift_app, options, confirmMessage=''):

	if confirmMessage != '':
		message(confirmMessage)
		answer = raw_input("~ Do you want to create local repo and fetch openshift application? [%s] " % "yes")

		answer = answer.strip().lower()
		if answer not in ['yes', 'y', '']:
			error_message("the local repo is not correct")

	if openshift_app == None:
		error_message("Application not found at openshift.")

	openshift_folder = os.path.join(app.path, '.openshift')
	
	#delete openshift folder to start it all over again
	if os.path.exists(openshift_folder): shutil.rmtree(openshift_folder)

	#could not delete openshift folder
	if os.path.exists(openshift_folder):
		error_message("ERROR - '%s' folder already exists and could not be deleted\nremove it and try again" % openshift_folder)

	os.mkdir(openshift_folder)
	if not os.path.exists(openshift_folder):
		error_message("ERROR - '%s' folder could not be created" % openshift_folder)

	app_folder = os.path.join(openshift_folder, options.app)
	if not os.path.exists(app_folder): os.mkdir(app_folder)
	if not os.path.exists(app_folder):
		error_message("ERROR - '%s' folder could not be created" % app_folder)

	#init repo
	out, err = shellexecute( ['git', 'init'], location=app_folder, msg="Creating git repo")
	if err != '':
		err.insert(0, "ERROR - error creating git repository at '%s'" % app_folder)
		error_message(err)
	
	#add remote
	out, err = shellexecute( ['git', 'remote', 'add', 'origin', openshift_app.repo], location=app_folder, msg="Adding %s as remote origin" % openshift_app.repo, debug=options.debug)
	if err != '':
		err.insert(0, "ERROR - error adding %s as a remote repo to '%s'" % (openshift_app.repo, app_folder))
		error_message(err)

	#fetch remote
	out, err = shellexecute( ['git', 'fetch', 'origin'], location=app_folder, msg="Fetching from origin...", debug=options.debug, output=True)
	#git fetch returns an errors, even if it works ok!
	#if err != '':
	#	err.insert(0, "ERROR - error fetching from origin (%s) repo" % (openshift_app.repo))
	#	error_message(err)

	#merge remote
	out, err = shellexecute( ['git', 'merge', 'origin/master'], location=app_folder, msg="Merging from origin/master", debug=options.debug)
	if err != '':
		err.insert(0, "ERROR - error merging from from origin/master (%s)" % (openshift_app.repo))
		error_message(err)

	local_repo_remove_default_app(app_folder, options)

	message("Repository at %s successfully created" % app_folder)

def local_repo_remove_default_app(app_folder, options):

	#remove useless openshift app
	if os.path.exists(os.path.join(app_folder, 'src')) or os.path.exists(os.path.join(app_folder, 'pom.xml')):
		#remove default app
		out, err = shellexecute( ['rm', '-fr', 'src', 'pom.xml'], location=app_folder, msg="Removing default app", debug=options.debug)
		if err != '':
			err.insert(0, "ERROR - error removing default application")
			error_message(err)

		out, err = shellexecute( ['git', 'add', '-A'], location=app_folder, debug=options.debug)
		if err != '':
			err.insert(0, "ERROR - error adding changes to be committed")
			error_message(err)

		out, err = shellexecute( ['git', 'commit', '-m', '"Removed default app"'], location=app_folder, debug=options.debug)
		if err != '':
			err.insert(0, "ERROR - error commiting changes")
			error_message(err)

		out, err = shellexecute( ['git', 'push', 'origin'], location=app_folder, msg="Pushing changes to origin...", debug=options.debug)
		#it works ok, but it reports an error...
		#if err != '':
		#	err.insert(0, "ERROR - error pushing changes to origin")
		#	error_message(err)

def openshift_info(options):
	info_cmd = ["rhc-user-info", "--apps"]

	if options.debug == True: info_cmd.append("-d")
	del options.debug

	for item in ["rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			info_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	out, err = shellexecute(info_cmd, True)

	if err != '':
		err.insert(0, "Failed to execute rhc-user-info, check that rhc-user-info is installed.")
		error_message(err)
	
def openshift_app(options):

	openshift_app = appinfo(options)

	if openshift_app == None:
		error_message("The application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))

	for key in openshift_app.__dict__:
		print '%s: %s' % (key, openshift_app.__dict__[key])

def appsinfo(options):

	info_cmd = ["rhc-user-info", "--apps", "--rhlogin=%s" % options.rhlogin]

	if options.password != '': info_cmd.append("--password=%s" % options.password)

	out, err = shellexecute(info_cmd, msg="Contacting openshift...", debug=options.debug)

	if err != '':
		err.insert(0, "Failed to execute rhc-user-info, check that rhc-user-info is installed.")
		error_message(err)
	
	return parseuserinfo(out)

def appinfo(options):
	apps = appsinfo(options)

	if not apps.has_key(options.app): return None

	return apps[options.app]

def message(lines):
	if isinstance(lines, str): lines = [lines]
	#print lines
	for line in lines: print "~ " + line.rstrip('\n')
	print "~"

def error_message(err):
	message(err)
	sys.exit(-1)

def shellexecute(params, output=False, location=None, debug=False, msg=None):

	#development
	#debug = True

	out, err, returncode = '', '', -1

	if msg != None: message(msg)

	if debug: message("about to execute: '" + " ".join(params) + "'")
	try:
		if location != None:
			if not os.path.exists(location):
				err = "directory '%s' does not exists" % location
				return out, err
			save_dir = os.getcwd()
			os.chdir(location)

		if output:
			returncode = subprocess.call(params)
		else:
			proc = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(out, err) = proc.communicate()
			returncode = proc.returncode

			#if output:
			#	if out != '': print out
			#	if err != '': print err

			if err != '': err = [err];			

		if returncode != 0:
			if err == '': err = []
			err.append("process returned code %s" % proc.returncode)

	except Exception as e:
		err = [ str(e), str(sys.exc_info()[0]) ]

	if err != '': 
		err.insert(0, "error executing: " + " ".join(params))

	if location != None: os.chdir(save_dir)

	if debug:
		print out
		print err

	return out, err

def parseuserinfo(data):
	apps, app = {}, None

	lines = data.splitlines()

	for line in lines:
		if ignoreline(line): continue
		if isApplication(line):
			if app != None: apps[app.name] = app
			app = openshift_application(line)        
		else:
			if line.find(":") != -1:
				line = line.strip().lower()
				key, value = line.split(":", 1)
				if key == "creation": app.creation = value.strip()
				if key == "framework": app.framework = value.strip()
				if key == "git url": app.repo = value.strip()
				if key == "public url": app.url = value.strip()

	#add last application
	if app != None: apps[app.name] = app

	return apps

def isApplication(line):
	if ignoreline(line): return False
	return not line.startswith(" ")

def ignoreline(line):
	return line == '' or startswithany(line, ["Contacting", "Application Info", "=="])

def startswithany(text, prefixes):
	for prefix in prefixes:
		if text.startswith(prefix):
			return True
	return False

class openshift_application:

	def __init__(self, name='', creation='', framework='', repo='', url=''):
		self.name, self.creation, self.framework, self.repo, self.url = \
		name, creation, framework, repo, url

	def __repr__(self):
		return 'name: %s, creation: %s, framework: %s, repo: %s, url: %s' % \
		(self.name, self.creation, self.framework, self.repo, self.url)

