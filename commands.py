import sys
import subprocess
import re
import os
import imp
import shutil
import webbrowser
import time
from datetime import datetime
from optparse import OptionParser

import play.commands.precompile

def import_module(module_name, file_path=""):
	if file_path == "": file_path = module_name + ".py"
	source = 	os.path.join(os.path.dirname(os.path.realpath(__file__)), file_path)
	return imp.load_source(module_name, source)

#custom imports
patched_war = import_module('patched_war')

MODULE = 'openshift'

# Commands that are specific to your module
COMMANDS = [
	"rhc:test", "rhc:hello", "rhc:chk", "rhc:deploy", "rhc:destroy", "rhc:logs", "rhc:info", "rhc:open"
]

HELP = {
	'rhc:chk': 			'Check openshift prerequisites, application and git repo.',
	'rhc:deploy': 	'Deploys application on openshift.',
	'rhc:destroy': 	'Destroys application on openshift.',
	'rhc:logs': 		'Show the logs of the application on openshift.',
	'rhc:info': 		'Displays information about user and configured applications.',
	'rhc:open': 		'Opens the application deployed on openshift in web browser.'
}

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
	parser.add_option("-m", "--message",    default='',  		dest="message",     help="Commit message")
	parser.add_option("",   "--timeout",    default='',     dest="timeout",     help="Timeout, in seconds, for connection")
	parser.add_option("-o", "--open",      	default=False,  dest="open",     		action="store_true", help="Open site after deploying")
	parser.add_option("-b", "--bypass",     default=False,  dest="bypass",     	action="store_true", help="Bypass warnings")

	options, args = parser.parse_args(args)

	if options.app == '': options.app = app.readConf('openshift.application.name')
	if options.app == '': options.app = app.readConf('application.name')

	if options.subdomain == '': options.subdomain = app.readConf('openshift.application.subdomain')

	if options.rhlogin == '': options.rhlogin = app.readConf('openshift.rhlogin')
	if options.rhlogin == '': error_message("You must provide your red hat's login using the -l RHLOGIN command line option or setting openshift.rhlogin in application.conf file.")

	if options.password == '': options.password = app.readConf('openshift.password')
	if options.password == '': error_message("You must provide your openshift password using the -p PASSWORD command line option or setting openshift.password in application.conf file.")

	if options.debug == False: options.debug = ( app.readConf('openshift.debug') in [True, '1', 'y', 'on', 'yes', 'enabled'] )

	if options.timeout == '': options.timeout = app.readConf('openshift.timeout')
	if options.timeout == '': del options.timeout

	app.check()

	#print options

	if command == "hello": 		print "~ Hello from openshift module"
	if command == "test": 		openshift_test(app, env, options)

	if command == "chk": 		  openshift_check(app, options)
	if command == "deploy": 	deploy_app(args, app, env, options)
	if command == "destroy": 	openshift_destroy(app, options)
	if command == "logs": 		openshift_logs(options)
	if command == "info": 		openshift_info(options)
	if command == "open": 		open_app(options)

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

def openshift_test(app, env, options):
	print "testing 1,2,3"

def deploy_app(args, app, env, options):
	check_appname(options.app)
	openshift_app = check_app(app, options)
	check_local_repo(app, openshift_app, options)

	app_folder = os.path.join(app.path, '.openshift', options.app)
	deploy_folder = os.path.join(app_folder, 'deployments')

	#delete deploy_folder folder to start it all over again
	if os.path.exists(deploy_folder): shutil.rmtree(deploy_folder)

	#could not delete deploy_folder folder
	if os.path.exists(deploy_folder):
		error_message("ERROR - '%s' folder already exists and could not be deleted\nremove it and try again" % deploy_folder)

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
	war_path = os.path.normpath(os.path.abspath(war_path))

	# Precompile first
	play.commands.precompile.execute(command='war', app=app, args=args, env=env)

	patched_war.package_as_war(app, env, war_path, war_zip_path=None, war_exclusion_list=['.openshift'])

	if not os.path.exists(war_path):
		error_message("ERROR - '%s' exploded war folder could not be created" % war_path)

	#add files
	out, err, ret = shellexecute( ['git', 'add', 'deployments'], location=app_folder, msg="Adding deployments folder to index", debug=options.debug, output=True)
	if err != '' or ret != 0:
		err.insert(0, "ERROR - error adding deployments folder to index (%s)" % (deploy_folder))
		error_message(err)

	commit_message = options.message
	if commit_message == '':	commit_message = 'deployed at ' + date
	commit_message = '"' + commit_message + '"'		

	out, err, ret = shellexecute( ['git', 'commit', '-m', commit_message], location=app_folder, msg="Commiting deployment", debug=options.debug, output=True)
	if err != '' or ret != 0:
		err.insert(0, "ERROR - error committing deployment")
		error_message(err)

	out, err, ret = shellexecute( ['git', 'push', 'origin'], location=app_folder, msg="Pushing changes to origin", debug=options.debug, output=True)
	if err != '' or ret != 0:
		err.insert(0, "ERROR - error pushing changes")
		error_message(err)

	if options.open == True: 
		message(["waiting 10 seconds before opening application, if it's not ready, just give openshift some time and press F5","if it's still not working try with 'play rhc:logs' to see what's going on"])
		time.sleep(10)
		open_app(options, openshift_app)
	else:
		message(["app successfully deployed", "issue play rhc:open to see it in action"])

def open_app(options, openshift_app=None):
	if openshift_app == None: openshift_app = appinfo(options)
	if openshift_app == None:
		error_message("the application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))

	url = openshift_app.url
	if options.subdomain != '': url = url.rstrip('/') + '/' + options.subdomain.strip('/')
	webbrowser.open(url, new=2)

def openshift_logs(options):
	create_cmd = ["rhc-tail-files"]

	if options.debug == True: create_cmd.append("-d")

	for item in ["app", "rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			create_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	out, err, ret = shellexecute( create_cmd, output=True, debug=options.debug, msg="Running rhc-tail-files")
	#will always return error 255, because user has to stop process	
	if err != '' and ret != 255:
		err.insert(0, "Failed to execute rhc-tail-files, check that rhc-tail-files is installed.")
		error_message(err)

def openshift_destroy(app, options):
	destroy_cmd = ["rhc-ctl-app"]

	if not options.bypass:
		message( [
			"!!!! WARNING !!!! WARNING !!!! WARNING !!!!", 
			"You are about to destroy the '%s' application." % options.app, 
			"", 
			"This is NOT reversible, all remote data for this application will be removed."
		] )

		answer = raw_input("~ Do you want to destroy this application (y/n): [%s] " % "no")

		answer = answer.strip().lower()
		if answer not in ['yes', 'y']:
			error_message("the application '%s' was not destroyed" % options.app)

	#first, clean up .openshift folder
	openshift_folder = os.path.join(app.path, '.openshift')

	#delete openshift_folder to leave everything clean
	if os.path.exists(openshift_folder): 
		message( "removing %s folder" % openshift_folder)
		shutil.rmtree(openshift_folder)

	#could not delete deploy_folder folder
	if os.path.exists(openshift_folder):
		error_message("ERROR - '%s' folder could not be deleted\nremove it and try again" % openshift_folder)

	if options.debug == True: create_cmd.append("--debug")

	destroy_cmd.append('--command=destroy')
	destroy_cmd.append('--bypass')

	for item in ["app", "rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			destroy_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	out, err, ret = shellexecute( destroy_cmd, output=True, debug=options.debug, msg="Running rhc-ctl-app --command=destroy --app=%s" % options.app)
	if err != '' and ret != 0:
		err.insert(0, "Failed to execute rhc-ctl-app, check that rhc-ctl-app is installed.")
		error_message(err)

def openshift_check(app, options):
	check_java(options)
	check_git(options)
	check_ruby(options)
	check_rhc(options)
	#check_rhc_chk(options)
	check_appname(options.app)
	openshift_app = check_app(app, options)
	check_local_repo(app, openshift_app, options)

def check_java(options):
	out, err, ret = shellexecute(["java", "-version"], debug=options.debug, raw_error=True)
	#java -version outputs to stderr
	if ret != 0:
		err.insert(0, "ERROR - Failed to execute 'java -version', check that java 1.6.x or lower is installed.")
		error_message(err)

	java_version = parse_java_version(err[0].splitlines())

	if java_version == '':
		err = "ERROR - Could not get java version executing 'java -version', check that java 1.6.x or lower is installed."
		error_message(err)

	if not (java_version < "1.7"):
		err = "ERROR - Java %s found. Java 1.7 or higher is not supported on openshift yet, check that java 1.6.x or lower is installed." % java_version
		error_message(err)

	message("OK! - checked java version: %s" % java_version)

def parse_java_version(lines):

	for line in lines:
		match = re.search("1\.[0-9]\.[0-9_]+", line)
		if match != None:
			break

	if match == None:
		return ""

	return match.group(0)


def check_git(options):
	out, err, ret = shellexecute(["git", "version"], debug=options.debug)
	if err != '' or ret != 0:
		err.insert(0, "ERROR - Failed to execute git, check that git is installed.")
		error_message(err)
	message("OK! - checked git version: %s" % out)

def check_ruby(options):
	out, err, ret = shellexecute(["ruby", "-v"], debug=options.debug)
	if err != '' or ret != 0:
		err.insert(0, "ERROR - Failed to execute ruby, check that ruby is installed.")
		error_message(err)
	message("OK! - checked ruby version: %s" % out)

def check_rhc(options):
	out, err, ret = shellexecute(["gem", "list", "rhc"], debug=options.debug)
	if err != '' or ret != 0:
		err.insert(0, "ERROR - Failed to execute gem list rhc, check that gem is installed.")
		error_message(err)
	message("OK! - checked rhc version: %s" % out)

def check_rhc_chk(options):
	check_cmd = ["rhc-chk"]

	if options.debug == True: create_cmd.append("-d")

	for item in ["rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			check_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	out, err, ret = shellexecute(check_cmd, output=True, debug=options.debug, msg="Running rhc-chk")
	if err != '' or ret != 0:
		err.insert(0, "Failed to execute rhc-chk, check that rhc-chk is installed.")
		error_message(err)

def check_appname(appname):
	if re.match("^[a-zA-Z0-9]+$", appname) == None:
		error_message( [
			"ERROR - Invalid application name: '%s'. It should only contain alphanumeric characters" % appname, 
			"You can change application's name from the 'application.name' setting " +
			"or specify a custom name for openshift application adding an 'openshift.application.name' setting " +
			"in your application.conf file."
		]
)
	message("OK! - checked application name: %s - OK!" % appname)

def check_app(app, options):
	openshift_app = appinfo(options)
	if openshift_app == None:

		if options.bypass == True:
			answer = 'yes'
		else:
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

	out, err, ret = shellexecute( ['git', 'status'], location=app_folder, debug=options.debug)
	if err != '' or ret != 0:
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - folder '%s' exists but does not seem to be a valid git repo" % git_folder )

	out, err, ret = shellexecute( ['git', 'remote', '-v'], location=app_folder, debug=options.debug)
	if err != '' or ret != 0:
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

		out, err, ret = shellexecute( create_cmd, location=openshift_folder, output=True, debug=options.debug, msg="Creating %s application at openshift" % options.app)
		if err != '' and ret != 0:
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

	if openshift_app == None:
		error_message("Application not found at openshift.")

	if confirmMessage != '':
		message(confirmMessage)
		answer = raw_input("~ Do you want to create local repo and fetch openshift application? [%s] " % "yes")

		answer = answer.strip().lower()
		if answer not in ['yes', 'y', '']:
			error_message("the local repo is not correct")

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
	out, err, ret = shellexecute( ['git', 'init'], location=app_folder, msg="Creating git repo")
	if err != '' and ret != 0:
		err.insert(0, "ERROR - error creating git repository at '%s'" % app_folder)
		error_message(err)
	
	#add remote
	out, err, ret = shellexecute( ['git', 'remote', 'add', 'origin', openshift_app.repo], location=app_folder, msg="Adding %s as remote origin" % openshift_app.repo, debug=options.debug)
	if err != '' and ret != 0:
		err.insert(0, "ERROR - error adding %s as a remote repo to '%s'" % (openshift_app.repo, app_folder))
		error_message(err)

	#fetch remote
	out, err, ret = shellexecute( ['git', 'fetch', 'origin'], location=app_folder, msg="Fetching from origin...", debug=options.debug, output=True)
	#git fetch returns an errors, even if it works ok!
	if err != '' and ret != 0:
		err.insert(0, "ERROR - error fetching from origin (%s) repo" % (openshift_app.repo))
		error_message(err)

	#merge remote
	out, err, ret = shellexecute( ['git', 'merge', 'origin/master'], location=app_folder, msg="Merging from origin/master", debug=options.debug)
	if err != '' and ret != 0:
		err.insert(0, "ERROR - error merging from from origin/master (%s)" % (openshift_app.repo))
		error_message(err)

	local_repo_remove_default_app(app_folder, options)

	message("Repository at %s successfully created" % app_folder)

def local_repo_remove_default_app(app_folder, options):

	#remove useless openshift app
	if os.path.exists(os.path.join(app_folder, 'src')) or os.path.exists(os.path.join(app_folder, 'pom.xml')):
		#remove default app
		out, err, ret = shellexecute( ['rm', '-fr', 'src', 'pom.xml'], location=app_folder, msg="Removing default app", debug=options.debug)
		if err != '' and ret != 0:
			err.insert(0, "ERROR - error removing default application")
			error_message(err)

		out, err, ret = shellexecute( ['git', 'add', '-A'], location=app_folder, debug=options.debug)
		if err != '' and ret != 0:
			err.insert(0, "ERROR - error adding changes to be committed")
			error_message(err)

		out, err, ret = shellexecute( ['git', 'commit', '-m', '"Removed default app"'], location=app_folder, debug=options.debug)
		if err != '' and ret != 0:
			err.insert(0, "ERROR - error commiting changes")
			error_message(err)

		out, err, ret = shellexecute( ['git', 'push', 'origin'], location=app_folder, msg="Pushing changes to origin...", debug=options.debug)
		#it works ok, but it reports an error...
		if err != '' and ret != 0:
			err.insert(0, "ERROR - error pushing changes to origin")
			error_message(err)

def openshift_info(options):
	info_cmd = ["rhc-domain-info", "--apps"]

	if options.debug == True: info_cmd.append("-d")
	del options.debug

	for item in ["rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			info_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	out, err, ret = shellexecute(info_cmd, output=True)
	if err != '' and ret != 0:
		err.insert(0, "Failed to execute rhc-domain-info, check that rhc-domain-info is installed.")
		error_message(err)
	
def openshift_app(options):

	openshift_app = appinfo(options)

	if openshift_app == None:
		error_message("The application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))

	for key in openshift_app.__dict__:
		print '%s: %s' % (key, openshift_app.__dict__[key])

def appsinfo(options):

	info_cmd = ["rhc-domain-info", "--apps", "--rhlogin=%s" % options.rhlogin]

	if options.password != '': info_cmd.append("--password=%s" % options.password)

	out, err, ret = shellexecute(info_cmd, msg="Contacting openshift...", debug=options.debug)
	if err != '' and ret != 0:
		err.insert(0, "Failed to execute rhc-domain-info, check that rhc-domain-info is installed.")
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

def shellexecute(params, output=False, location=None, debug=False, msg=None, raw_error=False):

	#development
	#debug = True

	out, err, ret = '', '', -1

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
			ret = subprocess.call(params)
		else:
			proc = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(out, err) = proc.communicate()
			ret = proc.returncode

			#if output:
			#	if out != '': print out
			#	if err != '': print err

			if err != '': err = [err];			

		if ret != 0:
			if err == '': err = []
			if not raw_error:
				err.append("process returned code %s" % ret)

	except Exception as e:
		err = [ str(e), str(sys.exc_info()[0]) ]

	if err != '' and not raw_error: 
		err.insert(0, "error executing: " + " ".join(params))

	if location != None: os.chdir(save_dir)

	if debug:
		print out
		print err

	return out, err, ret

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
