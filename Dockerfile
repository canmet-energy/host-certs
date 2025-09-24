# Unified Dockerfile for Certificate Testing
# Supports both WITH and WITHOUT corporate certificates using build args
ARG USE_CORPORATE_CERTS=true

FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Update package list and install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    ca-certificates \
    openssl \
    net-tools \
    dnsutils \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

# Create directory for custom certificates
RUN mkdir -p /usr/local/share/ca-certificates/

# Copy the certificate bundle and test script
COPY host.crt /tmp/host.crt
COPY scripts/test-connectivity.sh /usr/local/bin/test-connectivity.sh

# Use build arg to conditionally install corporate certificates
ARG USE_CORPORATE_CERTS
RUN if [ "$USE_CORPORATE_CERTS" = "true" ]; then \
        echo "Installing corporate certificates..."; \
        cp /tmp/host.crt /usr/local/share/ca-certificates/corporate-bundle.crt; \
        update-ca-certificates; \
        echo "Corporate certificates installed."; \
    else \
        echo "Skipping corporate certificates installation."; \
        update-ca-certificates; \
    fi

# Make test script executable
RUN chmod +x /usr/local/bin/test-connectivity.sh

# Set the working directory
WORKDIR /app

# Default command runs the connectivity test
CMD ["/usr/local/bin/test-connectivity.sh"]
