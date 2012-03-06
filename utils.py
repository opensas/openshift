import sys
import subprocess
import os
import shutil
import time
import re

def message(lines):
	if isinstance(lines, str): lines = [lines]
	#print lines
	for line in lines: print "~ " + line.rstrip('\n')
	print "~"

def error_message(err):
	message(err)
	sys.exit(-1)

def shellexecute(params, output=False, location=None, debug=False, msg=None, err_msg=None,
	raw_error=False, exit_on_error=False):

	#development
	#debug = True

	std_out, std_err, ret = '', '', -1
	err = ''

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
			(std_out, std_err) = proc.communicate()
			ret = proc.returncode

	except Exception as e:
		std_err = "Error %s (%s)" % ( str(e), str(sys.exc_info()[0]) )

	out = std_out

	#there was an error
	if std_err != '' or ret !=0: 
		if std_err != '':
			err = [std_err]
		else:
			err = []

		if not raw_error: err.insert(0, "error executing: %s (return code %s)" % (" ".join(params), ret ) )

	if location != None: os.chdir(save_dir)

	if debug:
		print "out: %s" % out
		print "err: %s" % err
		print "ret: %s" % ret

	if exit_on_error and (std_err != '' or ret != 0):
		if out != '': err.insert(0, out)
		if err_msg != None: 
			err.insert(0, err_msg)
		else:
			if msg != None: err.insert(0, "ERROR - error " + lowerFirst(msg))
		error_message(err)

	return out, err, ret

#returns True if text has at least a char in uppercase
def hasUpperChar(text):
	return (re.match("^.*[A-Z].*$", text) != None)

def lowerFirst(text):
	return text[:1].lower() + text[1:]

def elapsed(start):
	return format_time(time.time() - start)

def format_time(seconds):
	return "%d:%02d:%02d.%03d" % \
		reduce(lambda ll,b : divmod(ll[0],b) + ll[1:],
    [(seconds*1000,),1000,60,60])

def is_array(var):
	return isinstance(var, (list, tuple))

def remove_folder(folder, silent=False):
	#delete deploy_folder folder to start it all over again
	if os.path.exists(folder): 
		if not silent: message( "removing %s folder" % folder)
		shutil.rmtree(folder)

	if os.path.exists(folder):
		error_message("ERROR - '%s' folder already exists and could not be deleted\nremove it and try again" % folder)

def remove_file(file, silent=False):
	#delete deploy_folder folder to start it all over again
	if os.path.exists(file): 
		if not silent: message( "removing %s file" % file)
		os.remove(file)

	if os.path.exists(file):
		error_message("ERROR - '%s' file could not be deleted\nremove it and try again" % file)

def remove_fsobject(fs, silent=False):

	if os.path.isfile(fs): remove_file(fs, silent)
	if os.path.isdir(fs): remove_folder(fs, silent)

def remove_all(path, silent=False, exclude=[]):

	if not os.path.isdir(path): return "err: %s path not found" % path

	for file in os.listdir(path):

		if file in exclude:
			if not silent: message( "skipping %s" % file)
		else:
			remove_fsobject(os.path.join(path,file), silent)

	return ""

def move_all(source, target):

	if not os.path.isdir(source): return "err: source path %s not found" % source
	if not os.path.isdir(target): return "err: target path %s not found" % target

	for file in os.listdir(source):
		shutil.move(os.path.join(source,file), os.path.join(target,file))

	return ""

def create_folder(folder, silent=False):

	remove_folder(folder, silent=True)

	os.mkdir(folder)

	if not os.path.exists(folder):
		if not silent: message( "creating %s folder" % folder)
		error_message("ERROR - '%s' deployment folder could not be created" % folder)

