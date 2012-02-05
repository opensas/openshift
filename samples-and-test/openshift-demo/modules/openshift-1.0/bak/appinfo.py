import sys
import os

#add current dir to syspath to import local modules
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

#local imports
from utils import *

def appsinfo(options):

	info_cmd = ["rhc-domain-info", "--apps", "--rhlogin=%s" % options.rhlogin]

	if options.password != '': info_cmd.append("--password=%s" % options.password)

	out, err, ret = shellexecute( info_cmd, msg="Contacting openshift...", debug=options.debug, exit_on_error=True )

	return parseuserinfo(out)

def appinfo(options):
	apps = appsinfo(options)

	if not apps.has_key(options.app): return None

	return apps[options.app]

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
