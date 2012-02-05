import sys
import re
import os
import shutil
import webbrowser
import getpass

from datetime import datetime
from optparse import OptionParser

import play.commands.precompile

#add current dir to syspath to import local modules
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

#local imports
from utils import *
from appinfo import appinfo
import patched_war

MODULE = 'openshift'

# Commands that are specific to your module
COMMANDS = [
	"rhc:test", "rhc:hello", "rhc:chk", "rhc:fetch", "rhc:deploy", "rhc:destroy", "rhc:logs", "rhc:info", "rhc:open"
]

HELP = {
	'rhc:chk': 			'Check openshift prerequisites, application and git repo.',
	'rhc:fetch': 		'Fetches application from remote openshift repository.',
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
	parser.add_option("", "--use-remote",   default=False,  dest="use_remote",  action="store_true", help="Resolve conflicts using remote repository (openshift wins)")
	parser.add_option("", "--use-local",   	default=False,  dest="use_local",  	action="store_true", help="Resolve conflicts using local repository (you win)")

	options, args = parser.parse_args(args)

	if options.app == '': options.app = app.readConf('openshift.application.name')
	if options.app == '': options.app = app.readConf('application.name')

	if options.subdomain == '': options.subdomain = app.readConf('openshift.application.subdomain')

	if options.rhlogin == '': options.rhlogin = app.readConf('openshift.rhlogin')
	if options.rhlogin == '': 
		message("You must provide your openshift login using the -l RHLOGIN command line option or setting openshift.rhlogin in application.conf file.")
		options.rhlogin = raw_input("~ Enter your openshift login: ")
		if options.rhlogin == '': error_message("ERROR - No openshift login specified.")
		message("")

	if options.password == '': options.password = app.readConf('openshift.password')
	if options.password == '': 
		message("You must provide your openshift password using the -p PASSWORD command line option or setting openshift.password in application.conf file.")
		options.password = getpass.getpass("~ Enter your openshift password: ")
		if options.password == '': error_message("ERROR - No openshift login specified.")
		message("")

	if options.debug == False: options.debug = ( app.readConf('openshift.debug') in [True, '1', 'y', 'on', 'yes', 'enabled'] )

	if options.timeout == '': options.timeout = app.readConf('openshift.timeout')
	if options.timeout == '': del options.timeout

	app.check()

	#print options

	#test: foce use-local
	options.use_local = True

	if command == "hello": 		print "~ Hello from openshift module"
	if command == "test": 		openshift_test(app, env, options)

	if command == "chk": 		  openshift_check(app, options)
	if command == "fetch": 		openshift_fetch(args, app, env, options)
	if command == "deploy": 	openshift_deploy(args, app, env, options)
	if command == "destroy": 	openshift_destroy(app, options)
	if command == "logs": 		openshift_logs(options)
	if command == "info": 		openshift_info(options)
	if command == "open": 		openshift_open(options)

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
	check_app(app, options)

def openshift_fetch(args, app, env, options):
	
	openshift_app = check_app(app, options)

	if not options.bypass:
		message( [
			"!!!! WARNING !!!! WARNING !!!! WARNING !!!!", 
			"You are about to destroy your local application and local git repository", 
			"and we will clone your openshift '%s' git repository" % options.app, 
			"This is NOT reversible, all remote data for this application will be removed."
		] )

		answer = raw_input("~ Do you want to destroy your local application (y/n): [%s] " % "no")

		answer = answer.strip().lower()
		if answer not in ['yes', 'y']:
			error_message("openshift application fetch canceled")

	try:

		app_folder = app.path

		#clone the repo into a tmp folder
		tmp_folder = os.path.join(app_folder, '.tmp')

		create_folder(tmp_folder)

		shellexecute( ['git', 'clone', openshift_app.repo], location=tmp_folder, debug=options.debug, exit_on_error=True,
			msg="Clonning openshift repo at (%s)" % tmp_folder, output=True )
	
		cloned_app_folder = os.path.join(tmp_folder, openshift_app.name)

		message("removing local app at %s" % app_folder)
		remove_all(app_folder, exclude=['.tmp'], silent=True)

		move_all(cloned_app_folder, app_folder)

		message("application succesfully fetched")

	finally:
		remove_folder(tmp_folder)

def openshift_deploy(args, app, env, options, openshift_app=None):
	start = time.time()

	check_appname(options.app)

	if openshift_app == None: openshift_app = check_app(app, options)				# check remote repo
	if openshift_app == None: error_message("ERROR - '%s' application not found at openshift" % options.app)

	check_local_repo(app, openshift_app, options) # check local repo

	commit_local_repo(app, options)

	merge_repos(app, openshift_app, options)			# merge local and remote repo

	app_folder = app.path
	deploy_folder = os.path.join(app_folder, 'deployments')

	create_folder(deploy_folder)

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

	start_war = time.time()

	patched_war.package_as_war(app, env, war_path, war_zip_path=None, war_exclusion_list=['deployments'])

	if not os.path.exists(war_path):
		error_message("ERROR - '%s' exploded war folder could not be created" % war_path)

	message([ "", "war successfully generated to %s in %s" % ( war_path, elapsed(start) ) ])

	precompiled_folder = os.path.join(app_folder, 'precompiled')
	remove_folder(precompiled_folder)

	#add files
	shellexecute( ['git', 'add', 'deployments'], location=app_folder, debug=options.debug, exit_on_error=True,
		msg="Adding deployments folder index (%s)" % deploy_folder, output=True )

	commit_message = options.message
	commit_message = 'deployed at ' + date
	if options.message != '': commit_message += " (%s)" % options.message
	commit_message = '"' + commit_message + '"'		

	shellexecute( ['git', 'commit', '-m', commit_message], location=app_folder, 
		msg="Commiting deployment", debug=options.debug, output=True, exit_on_error=True )

	shellexecute( ['git', 'push', 'origin', '--force'], location=app_folder, 
		msg="Pushing changes to origin", debug=options.debug, output=True, exit_on_error=True)

	message([ "", "app successfully deployed in %s" % elapsed(start) ])

	if options.open == True: 
		message([
			"waiting 10 seconds before opening application, if it's not ready, just give openshift some time and press F5",
			"if it's still not working try with 'play rhc:logs' to see what's going on"
		])
		time.sleep(10)
		openshift_open(options, openshift_app)
	else:
		message("issue play rhc:open to see your application running on openshift")

def openshift_open(options, openshift_app=None):
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

	out, err, ret = shellexecute( create_cmd, output=True, debug=options.debug, 
		msg="Running rhc-tail-files", exit_on_error=False )
	#will always return error 255, because user has to stop process	
	if err != '' and ret != 255:
		err.insert(0, "Failed to execute rhc-tail-files, check that rhc-tail-files is installed.")
		error_message(err)

def openshift_destroy(app, options):
	start = time.time()

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

	app_folder = app.path

	openshift_app = appinfo(options)

	if openshift_app != None:

		destroy_cmd = ["rhc-ctl-app"]

		if options.debug == True: destroy_cmd.append("--debug")

		destroy_cmd.append('--command=destroy')
		destroy_cmd.append('--bypass')

		for item in ["app", "rhlogin", "password", "timeout"]:
			if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
				destroy_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

		shellexecute( destroy_cmd, output=True, debug=options.debug, 
			msg="Destroy application %s" % options.app, exit_on_error=True)

	else:
		message( "application %s does not exist on openshit. skipping destroy." % options.app )

	#delete local files
	message("deleting .git, deployments, .openshift folders and .gitignore file at %s" % app_folder)
	remove_folder(os.path.join(app_folder, '.git'))
	remove_folder(os.path.join(app_folder, 'deployments'))
	remove_folder(os.path.join(app_folder, '.openshift'))
	remove_file(os.path.join(app_folder, '.gitignore'))

	message([ "app successfully removed from openshift in %s" % elapsed(start) ])

def openshift_check(app, options):
	check_java(options)
	check_git(options)
	check_ruby(options)
	check_rhc(options)
	
	check_appname(options.app)
	openshift_app = check_app(app, options)
	check_local_repo(app, openshift_app, options)
	check_rhc_chk(options)

def check_java(options):
	out, err, ret = shellexecute(["java", "-version"], debug=options.debug, raw_error=True, exit_on_error=False)
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
		if match != None: break

	if match == None: return ""

	return match.group(0)

def check_git(options):
	out, err, ret = shellexecute(["git", "version"], debug=options.debug,
		err_msg="Failed to execute git, check that git is installed.", exit_on_error=True )
	message("OK! - checked git version: %s" % out)

def check_ruby(options):
	out, err, ret = shellexecute(["ruby", "-v"], debug=options.debug,
		err_msg="Failed to execute ruby, check that ruby is installed.", exit_on_error=True )
	message("OK! - checked ruby version: %s" % out)

def check_rhc(options):
	out, err, ret = shellexecute(["gem", "list", "rhc", "--local"], debug=options.debug,
		err_msg="Failed to execute gem list rhc, check that gem is installed.", exit_on_error=True )

	#0.84.15 or higher
	if "rhc " not in out:
		error_message("rhc ruby gem not found. Try installing it with 'gem install rhc'")

	versions = re.findall("\d{1,2}\.\d{1,2}\.\d{1,2}",out)

	if len(versions) == 0:
		error_message("no version of rhc ruby gem found. Try installing it with 'gem install rhc'")

	#check current version
	current = versions[0] 
	if current < "0.84.15":
		error_message( [
			"the latest rhc ruby gem version found on your system is %s" % current,
			"openshift module requires rhc ruby gem 0.8.15 or higher, you can upgrade it running 'gem update rhc'"
		] )

	message("OK! - checked rhc version: %s" % out)

	if len(versions) > 1:
		message( [
			"Tip: you have %s versions of rhc ruby gem installed." % len(versions),
			"You can remove old versions running 'gem cleanup rhc'."
		] )

def check_rhc_chk(options):
	check_cmd = ["rhc-chk"]

	if options.debug == True: create_cmd.append("-d")

	for item in ["rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			check_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	shellexecute(check_cmd, output=True, debug=options.debug, 
		msg="Running rhc-chk", err_msg="Failed to execute rhc-chk, check that rhc-chk is installed.", exit_on_error=True)

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

#
# Verifies that application exists at openshift, and returns it's information
#
# If it doesn't exist, it asks the user to create it
# 
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

	app_folder = app.path

	git_folder = os.path.join(app_folder, '.git')
	if not os.path.exists(git_folder):
		create_local_repo(app, openshift_app, options, confirmMessage="!!! - '%s' does not seem to be a valid git repository, .git folder not found." % app_folder )

	out, err, ret = shellexecute( ['git', 'status'], location=app_folder, debug=options.debug, exit_on_error=False)
	if err != '' or ret != 0:
		create_local_repo(app, openshift_app, options, confirmMessage="ERROR - folder '%s' exists but does not seem to be a valid git repo." % git_folder )

	out, err, ret = shellexecute( ['git', 'remote', '-v'], location=app_folder, debug=options.debug, exit_on_error=False)
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
		create_local_repo(app, openshift_app, options, 
			confirmMessage="ERROR - could not found remote '%s' in '%s' git repo" % (openshift_app.repo, git_folder) )

	#create .gitignore file
	gitignore_dest = os.path.join(app_folder, '.gitignore')
	if not os.path.exists(gitignore_dest):
		gitignore_src = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'resources', 'gitignore')
		shutil.copyfile(gitignore_src, gitignore_dest)

		if not os.path.exists(gitignore_dest):
			error_message("Could not create .gitignore file at %s" % gitignore_dest)

	message("OK! - folder '%s' exists and seems to be a valid git repo" % git_folder)

def create_app(app, options):

	openshift_app = appinfo(options)

	#create openshift application
	if openshift_app == None:

		tmp_folder = os.path.join(app.path, '.tmp')

		try:

			create_folder(tmp_folder)

			start = time.time()

			create_cmd = ["rhc-create-app", "--type", 'jbossas-7.0']

			if options.debug == True: create_cmd.append("-d")

			for item in ["app", "rhlogin", "password", "timeout"]:
				if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
					create_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

			shellexecute( create_cmd, location=tmp_folder, debug=options.debug, output=True,
				msg="Creating %s application at openshift" % options.app, exit_on_error=True )

			openshift_app = appinfo(options)
			if openshift_app == None: error_message("Failed to create app, check that rhc-create-app is installed.")

			app_folder = os.path.join(tmp_folder, options.app)
			local_repo_remove_default_app(app_folder, options)

			message( "Application %s successfully created at %s in %s" % (options.app, app_folder, elapsed(start)) )

		finally:
			remove_folder(tmp_folder, silent=True)

	return openshift_app

def create_local_repo(app, openshift_app, options, confirmMessage=''):

	app_folder = app.path

	if openshift_app == None:
		error_message("Application not found at openshift.")

	if confirmMessage != '':
		message(confirmMessage)
		answer = raw_input("~ Do you want to create your local repo and merge openshift application? [%s] " % "yes")

		answer = answer.strip().lower()
		if answer not in ['yes', 'y', '']:
			error_message("the local repo is not correct")

	#init repo
	shellexecute( ['git', 'init'], location=app_folder, debug=options.debug,
		msg="Creating git repo at '%s'" % app_folder, exit_on_error=True )
	
	#add remote
	shellexecute( ['git', 'remote', 'add', 'origin', openshift_app.repo], location=app_folder, debug=options.debug,
		msg="Adding %s as a remote repo to '%s'" % (openshift_app.repo, app_folder), exit_on_error=True )

	#just in case the default openshift app is there
	local_repo_remove_default_app(app_folder, options)

	message("Local git repository at %s successfully created" % app.path)

def commit_local_repo(app, options):

	app_folder = app.path	

	#add files
	shellexecute( ['git', 'add', '-A'], location=app_folder, debug=options.debug, exit_on_error=True,
		msg="Adding changes to index", output=True )

	#add files
	out, err, ret = shellexecute( ['git', 'status'], location=app_folder, debug=options.debug, exit_on_error=True,
		msg="Checking for files to commit", output=False )

	#nothing to do, already committed
	if "nothing to commit" in out: return

	date = str(datetime.now())
	commit_message = options.message
	if commit_message == '':	commit_message = 'commiting at ' + date
	commit_message = '"' + commit_message + '"'		

	shellexecute( ['git', 'commit', '-m', commit_message], location=app_folder, 
		msg="Commiting changes", debug=options.debug, output=True, exit_on_error=True )

def merge_repos(app, openshift_app, options):

	#fetch remote
	shellexecute( ['git', 'fetch', 'origin'], location=app.path, debug=options.debug,
		msg="fetching from origin (%s) repo" % openshift_app.repo, output=True, exit_on_error=True )

	conflict = False
	use_local = options.use_local
	use_remote = options.use_remote

	# no strategy specified for solving conflicts
	if not use_local and not use_remote:

		#merge remote
		out, err, ret = shellexecute( ['git', 'merge', 'origin/master'], location=app.path, debug=options.debug, 
			msg="Merging from origin/master (%s)" % openshift_app.repo, exit_on_error=False )

		#Conflicts detected
		if ret == 1 and "CONFLICT" in out:

			concflict = True
			message(out)
			message( [ "",
				"Attention!, conflicts detected when trying to merge changes from openshift repo.",
				"You have the following options:",
				"(L) Use your local version to solve conflicts, changes from remote repo will be overwritten (same as using --use-local).",
				"(R) Use remote version to solve conflicts, changes from your local repo will be overwritten (same as using --use-remote).",
				"(M) Manually solve conflicts: look the above files and manually edit them to solve conflicts.",
				"    After manually solving your issues youl'll have to redeploy your app.",
				"(C) Cancel merge." 
			] )
			answer = raw_input("~ Choose your option %s %s %s %s or press enter for Local: " % ("[L]ocal", "[R]emote", "[M]anual", "[C]ancel")  )

			answer = answer.strip().lower()

			if answer == '': answer = 'l'

			print "answer: %s" % answer
			
			if answer in ['m', 'manual']: 
				error_message( [ 
					"You'll have to manually edit the files to solve the files in conflict.",
					"After that run play rhc:deploy once again to deploy your changes.",
				] )

			#back to last commit
			our, err, ret = shellexecute( ['git', 'reset', '--hard', 'HEAD'], location=app.path, debug=options.debug, 
				msg="Reverting to last commit", exit_on_error=True )

			if answer in ['c', 'cancel']:
				error_message( "Merge from remote repo at openshift has been canceled." )

			if answer in ['l', 'local', '']: use_local = True

			if answer in ['r', 'remote']: use_remote = True

			#invalid answer
			if answer not in ['c', 'cancel', 'l', 'local', 'r', 'remote', 'm', 'manual']:
				error_message( "Invalid answer, canceled merge with remote repo at openshift." )

		if ret != 0 or err != '': error_message(err)

		if ret == 0 and err == '':
			message( "Remote repository at openshift successfully merged with local repository." )
			return

	if conflict == True and (not use_local) and (not use_remote):
		error_message( [
			"Conflict has been detected and no strategy has been specified.",
			"Use play rhc_deploy with the --use-local or --use-remote option."
		] )

	merge_command = ['git', 'merge', '-s', 'recursive', '-X']
	
	if use_local: merge_command.append("ours")
	if use_remote: merge_command.append("theirs")

	merge_command.append("origin/master")

	#merge remote
	our, err, ret = shellexecute( merge_command, location=app.path, debug=options.debug, 
		msg="Merging from origin/master (%s)" % openshift_app.repo, exit_on_error=True )

def local_repo_remove_default_app(repo_folder, options):
	
	commit_changes = False

	#remove useless openshift app
	src_folder = os.path.join(repo_folder, 'src')
	if os.path.exists(src_folder): 
		commit_changes = True
		remove_folder(src_folder, silent=True)

	pom_file = os.path.join(repo_folder, 'pom.xml')
	if os.path.exists(pom_file):
		commit_changes = True
		remove_file(pom_file, silent=True)

	gitignore_file = os.path.join(repo_folder, '.gitignore')
	if os.path.exists(gitignore_file):
		commit_changes = True
		remove_file(gitignore_file, silent=True)

	if commit_changes:

		shellexecute( ['git', 'add', '-A'], location=repo_folder, debug=options.debug, 
			msg="Adding changes to be committed (removing default app)", exit_on_error=True )

		shellexecute( ['git', 'commit', '-m', '"Removed default app"'], location=repo_folder, debug=options.debug,
			msg="Committing changes (removing default app)", exit_on_error=True )

		#we'll push it right now, because we will delete the local repo
		shellexecute( ['git', 'push', 'origin'], location=repo_folder, 
			msg="Pushing changes to origin... (removing default app)", debug=options.debug, output=True, exit_on_error=True)

def openshift_info(options):
	info_cmd = ["rhc-domain-info", "--apps"]

	if options.debug == True: info_cmd.append("-d")
	del options.debug

	for item in ["rhlogin", "password", "timeout"]:
		if hasattr(options, item) and eval('options.%s' % item) != None and eval('options.%s' % item) != '':
			info_cmd.append("--%s=%s" % (item, eval('options.%s' % item)))

	shellexecute( info_cmd, output=True, 
		msg="Getting information for %s account" % options.rhlogin, exit_on_error=True )
	
def openshift_app(options):

	openshift_app = appinfo(options)

	if openshift_app == None:
		error_message("The application '%s' does not exist for login '%s' in openshift" % (options.app, options.rhlogin))

	for key in openshift_app.__dict__:
		print '%s: %s' % (key, openshift_app.__dict__[key])


