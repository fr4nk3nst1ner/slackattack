import os
import re

# Get the current directory (where get_version.py is located)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Build the path to _version.py in the slackattack/ directory
version_file_path = os.path.join(current_dir, "slackattack", "_version.py")

# Open and read the _version.py file
with open(version_file_path, "r") as f:
    version_file = f.read()

# Extract the version number using regex
version_match = re.search(r'__version__ = ["\']([^"\']*)["\']', version_file)

if version_match:
    print(version_match.group(1))
else:
    raise ValueError("Version not found in _version.py")
