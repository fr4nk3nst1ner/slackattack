# export env vars 
export GITHUB_TOKEN=
export PYPI_API_TOKEN=

# build docker container 
docker build -t github-actions-test .
docker run -it --rm -v /opt/slackattack:/workspace github-actions-test

# run this inside docker container 

# Install dependencies
python3 -m pip install --upgrade pip
python3 -m pip install setuptools wheel build bump2version twine

# Clean and Build the package
rm -rf dist
python3 -m build --sdist --wheel --outdir dist --no-isolation

# Publish the package (optional, you might skip this to avoid actual publishing)
# twine upload dist/*  # This would actually publish your package

