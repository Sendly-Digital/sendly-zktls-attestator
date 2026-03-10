# Stage 1: Build zktls CLI from source
FROM rust:latest AS zktls-builder

WORKDIR /usr/src/zktls

# Install additional dependencies for zktls build
RUN apt-get update && apt-get install -y git cmake clang libclang-dev && rm -rf /var/lib/apt/lists/*

# Clone zktls repository
RUN git clone https://github.com/the3cloud/zktls.git .

# Build zktls in release mode
RUN cargo build --release
 
# Stage 2: Runtime environment 
FROM node:20-slim AS runtime 
 
# Install system dependencies 
RUN apt-get update && apt-get install -y build-essential python3 libgomp1 curl ca-certificates && rm -rf /var/lib/apt/lists/* 
 
# Copy zktls binary from builder stage 
COPY --from=zktls-builder /usr/src/zktls/target/release/zktls /usr/local/bin/zktls 
RUN chmod +x /usr/local/bin/zktls 
 
# Create non-root user 
RUN useradd --create-home --shell /bin/bash appuser 
 
WORKDIR /home/appuser/app 
 
# Copy package files 
COPY package.json package-lock.json ./ 
 
# Install production dependencies only 
RUN npm ci --only=production 
 
# Copy application code 
COPY server.js ./ 
 
# Change ownership to appuser 
RUN chown -R appuser:appuser /home/appuser/app 
 
# Switch to non-root user 
USER appuser 
 
# Expose port 
EXPOSE 3001 
 
# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:3001/api/health || exit 1

# Environment variables
ENV NODE_ENV=production PORT=3001 ZKTLS_PATH=/usr/local/bin/zktls ZKTLS_BACKEND=r0 
 
# Copy entrypoint script 
COPY --chown=appuser:appuser docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "server.js"]
