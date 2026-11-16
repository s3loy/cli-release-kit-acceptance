import os, subprocess
binary = os.environ["KIT_BINARY"]
def run(program, data=""):
    return subprocess.run([binary, program], input=data, text=True, capture_output=True)
result = run("BEGIN { print 6 * 7 }")
assert result.returncode == 0 and result.stdout == "42\n", result
result = run("{ sum += $1 } END { print sum }", "2\n3\n")
assert result.returncode == 0 and result.stdout == "5\n", result
result = run('BEGIN { print toupper("Hello") }')
assert result.returncode == 0 and result.stdout == "HELLO\n", result
result = run("BEGIN {")
assert result.returncode != 0 and result.stderr, result
print("GoAWK archived interpreter behavior passed")
