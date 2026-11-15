import json,os,subprocess
v=json.loads(subprocess.check_output([os.environ["KIT_BINARY"],"--json"]))
assert v=={"message":"chirp","ok":True},v
