FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    python3 python3-pip git curl

# Install specific versions of tools as needed
RUN python3 -m pip install --upgrade pip setuptools wheel

# Set up environment variables as they would be in GitHub Actions
ENV GITHUB_WORKSPACE=/workspace
WORKDIR $GITHUB_WORKSPACE

# Copy your workflow files (optional)
COPY . $GITHUB_WORKSPACE

