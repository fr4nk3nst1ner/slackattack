import os
import re

# Get the current directory (where _version.py should be located)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Open and read the _version.py file
with open(os.path.join(current_dir, "_version.py"), "r") as f:
    version_file = f.read()

# Extract the version number using regex
version_match = re.search(r'__version__ = ["\']([^"\']*)["\']', version_file)

if version_match:
    print(version_match.group(1))
else:
    raise ValueError("Version not found in _version.py")
