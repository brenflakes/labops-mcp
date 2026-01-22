FROM python:3.12-slim

# Install SSH client for ssh_exec tool
RUN apt-get update && \
    apt-get install -y openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir fastmcp httpx pyyaml jq

WORKDIR /app

# Copy server code
COPY server.py .
COPY audit.py .

# Setup SSH directory with ControlMaster config
RUN mkdir -p /root/.ssh/sockets && \
    chmod 700 /root/.ssh /root/.ssh/sockets && \
    echo "Host *\n\
    ControlMaster auto\n\
    ControlPath /root/.ssh/sockets/%r@%h-%p\n\
    ControlPersist 600\n\
    StrictHostKeyChecking accept-new\n\
    ConnectTimeout 5" > /root/.ssh/config && \
    chmod 600 /root/.ssh/config

EXPOSE 8100

CMD ["python", "server.py"]
