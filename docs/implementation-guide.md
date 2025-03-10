# AutonomAuth Comprehensive Implementation Guide

## System Overview

AutonomAuth is a decentralized authentication system that uses the Autonomi network to store user identity and authentication data. This guide provides detailed information for developers and system administrators to implement, deploy, and maintain the AutonomAuth system.

## Table of Contents

1. [Architecture](#architecture)
2. [Components](#components)
3. [Prerequisites](#prerequisites)
4. [Setup and Installation](#setup-and-installation)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
8. [Integration Guide](#integration-guide)
9. [Security Considerations](#security-considerations)
10. [Troubleshooting](#troubleshooting)

## Architecture

AutonomAuth uses a microservices architecture with containerized components managed by Docker Compose. This approach provides scalability, maintainability, and isolation between different parts of the system.

### System Architecture Diagram

![System Architecture](system-architecture-diagram.png)

### Data Flow

1. **Authentication Flow**:
   - User scans QR code on website using mobile app
   - App signs challenge with derived key
   - Website verifies signature with AutonomAuth server
   - Server creates session and returns token
   - Website grants access based on token

2. **Data Storage Flow**:
   - User data stored on Autonomi network
   - Authentication sessions stored on both Autonomi and Redis
   - Challenge data stored temporarily in Redis
   - Website receives only necessary verification results

## Components

### Core Components

1. **Core Rust Library** (`autonomauth`):
   - Cryptographic functions (key derivation, signatures)
   - Autonomi network integration
   - Data models and storage abstractions
   - Error handling

2. **Server Microservices**:
   - **API Gateway** (`nginx`): Routes requests and handles SSL termination
   - **Auth Service**: Main authentication logic
   - **Challenge Service**: Creates and verifies authentication challenges
   - **Session Service**: Manages authentication sessions
   - **Notification Service**: Sends push notifications to users

3. **Mobile App Components**:
   - **Rust Core**: Business logic with FFI exposure
   - **React Native Module**: JavaScript bridge for mobile apps
   - **iOS Module**: Swift implementation for iOS
   - **Android Module**: Java implementation for Android

4. **Web Components**:
   - **React Widget**: React component for websites
   - **JavaScript Library**: Core functionality for web integration
   - **TypeScript Definitions**: Type safety for developers

5. **Supporting Services**:
   - **Redis**: For caching and rate limiting
   - **Prometheus**: For monitoring and metrics
   - **Grafana**: For visualization of metrics
   - **Certbot**: For SSL certificate management

### Container Architecture

```
AutonomAuth
├── API Gateway (Nginx)
│   ├── SSL Termination (Certbot)
│   ├── Rate Limiting
│   └── Request Routing
├── Auth Service
│   ├── User Authentication
│   └── Profile Management
├── Challenge Service
│   ├── Challenge Creation
│   └── QR Code Generation
├── Session Service
│   ├── Session Management
│   └── Session Verification
├── Notification Service
│   ├── Push Notifications
│   └── Device Registration
├── Supporting Services
│   ├── Redis
│   ├── Prometheus
│   └── Grafana
└── Autonomi Client
    └── Network Connection
```

## Prerequisites

### Hardware Requirements

- **CPU**: Minimum 2 cores, recommended 4+ cores
- **RAM**: Minimum 4GB, recommended 8GB+
- **Storage**: Minimum 20GB SSD, recommended 50GB+ SSD
- **Network**: Stable internet connection with minimum 5 Mbps upload/download

### Software Requirements

- **Operating System**: Ubuntu 20.04 LTS or newer (recommended), Debian 11+, or CentOS 8+
- **Docker**: Version 20.10.x or newer
- **Docker Compose**: Version 2.0.0 or newer
- **Git**: Version 2.25.0 or newer
- **Domain Name**: Registered domain name pointed to server IP
- **Ports**: 80 and 443 accessible from the internet

### Autonomi Network Requirements

- **Autonomi Client**: Access to Autonomi network
- **ANT Tokens**: For storage payments
- **ETH on Arbitrum**: For gas fees

## Setup and Installation

### Comprehensive Server Setup

1. **Prepare the Server**:

   ```bash
   # Update system packages
   sudo apt update && sudo apt upgrade -y
   
   # Install required dependencies
   sudo apt install -y \
       apt-transport-https \
       ca-certificates \
       curl \
       gnupg \
       lsb-release \
       git
   ```

2. **Install Docker**:

   ```bash
   # Add Docker's official GPG key
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
   
   # Add Docker repository
   echo \
     "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
     $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   
   # Install Docker Engine
   sudo apt update
   sudo apt install -y docker-ce docker-ce-cli containerd.io
   
   # Add current user to docker group to avoid using sudo
   sudo usermod -aG docker $USER
   
   # Apply group changes (you may need to logout and login again)
   newgrp docker
   ```

3. **Install Docker Compose**:

   ```bash
   # Install Docker Compose
   sudo curl -L "https://github.com/docker/compose/releases/download/v2.15.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   
   # Apply executable permissions
   sudo chmod +x /usr/local/bin/docker-compose
   
   # Verify installation
   docker-compose --version
   ```

4. **Clone the Repository**:

   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/autonomauth.git
   cd autonomauth
   ```

5. **Run the Setup Script**:

   ```bash
   # Make setup script executable
   chmod +x setup.sh
   
   # Run setup script
   ./setup.sh
   ```

### Configuration for Local Development

For local development or testing, you can use the provided setup script with development certificates:

```bash
# Generate development certificates and prepare directory structure
./setup.sh --dev
```

This will create self-signed certificates for development purposes and set up the required directory structure.

### Configuration for Production

For production environments, use the Let's Encrypt script after updating your domain name in the `.env` file:

```bash
# Edit .env file first to set your domain and email
nano .env

# Then run the Let's Encrypt initialization script
chmod +x init-letsencrypt.sh
./init-letsencrypt.sh
```

## Configuration

### Environment Variables

The system uses a `.env` file to manage configuration. Here's a detailed explanation of each variable:

```bash
# Autonomi Network Configuration
AUTONOMAUTH_STORAGE_KEY=<hex_encoded_storage_key>  # Storage key for Autonomi network
AUTONOMAUTH_TESTNET=true/false  # Whether to use testnet (true) or mainnet (false)
AUTONOMI_NETWORK=testnet/mainnet  # Network to connect to
AUTONOMI_WALLET_KEY=<wallet_private_key>  # Private key for Autonomi wallet

# Domain Configuration
DOMAIN_NAME=auth.example.com  # Your domain name
EMAIL_ADDRESS=admin@example.com  # Email for Let's Encrypt notifications

# API Configuration
PORT=3000  # Default port for the main API
API_KEY=<random_string>  # API key for internal service communication
RATE_LIMIT_MAX=100  # Maximum requests per window
RATE_LIMIT_WINDOW=60  # Window size in seconds

# Redis Configuration
REDIS_URL=redis://redis:6379  # Redis connection URL
REDIS_PASSWORD=  # Optional Redis password

# Monitoring
GRAFANA_ADMIN_USER=admin  # Grafana admin username
GRAFANA_ADMIN_PASSWORD=<secure_password>  # Grafana admin password

# Push Notifications
FIREBASE_CREDENTIALS=<path_to_firebase_credentials.json>  # Path to Firebase credentials file
```

### Nginx Configuration

The Nginx configuration is automatically set up by the setup script, but you can customize it further by editing the files in the `nginx/` directory:

- `nginx/nginx.conf`: Main Nginx configuration
- `nginx/conf.d/default.conf`: Site-specific configuration

Important settings to review:

- SSL certificate paths
- Security headers
- Rate limiting parameters
- Proxy settings

### Prometheus Configuration

The Prometheus configuration is located at `prometheus/prometheus.yml` and can be customized to monitor additional metrics or change scrape intervals.

## Deployment

### Starting the Services

```bash
# Start all services in detached mode
docker-compose up -d
```

This will start all the services defined in the `docker-compose.yml` file, including:

- API Gateway (Nginx)
- SSL Certificate Manager (Certbot)
- Auth Service
- Challenge Service
- Session Service
- Notification Service
- Autonomi Client
- Redis
- Prometheus
- Grafana

### Verifying Deployment

```bash
# Check if all containers are running
docker-compose ps

# Check logs of a specific service
docker-compose logs auth-service

# Follow logs in real-time
docker-compose logs -f nginx
```

### Scaling Services

For higher traffic environments, you can scale certain services:

```bash
# Scale auth service to 3 instances
docker-compose up -d --scale auth-service=3

# Scale challenge service to 2 instances
docker-compose up -d --scale challenge-service=2
```

Note that when scaling services, you may need to update the Nginx configuration to properly load balance between instances.

### Updating Services

To update services with new versions:

```bash
# Pull the latest changes
git pull

# Rebuild and restart the services
docker-compose down
docker-compose build
docker-compose up -d
```

For zero-downtime updates of specific services:

```bash
# Update a specific service
docker-compose build auth-service
docker-compose up -d --no-deps auth-service
```

## Monitoring and Maintenance

### Health Checks

All services expose health check endpoints:

```
GET /api/health
```

These can be used by monitoring tools to verify service health.

### Metrics

Prometheus metrics are available at:

```
https://auth.example.com/monitoring/prometheus/
```

Grafana dashboards for visualizing metrics:

```
https://auth.example.com/monitoring/grafana/
```

Default Grafana login: `admin` / `<password from .env>`

### Important Metrics to Monitor

- **Request Rate**: Number of authentication requests per second
- **Error Rate**: Percentage of failed authentication attempts
- **Response Time**: Average time to respond to authentication requests
- **CPU Usage**: Per-service CPU utilization
- **Memory Usage**: Per-service memory utilization
- **Autonomi Network Health**: Connection status and replication metrics

### Log Management

Logs are stored in the `logs/` directory and can be accessed via Docker Compose:

```bash
# View logs of a specific service
docker-compose logs auth-service

# Follow logs in real-time with timestamps
docker-compose logs -f --timestamps nginx

# View last 100 lines of logs
docker-compose logs --tail=100 challenge-service
```

For production deployments, consider setting up a centralized logging solution such as ELK Stack or Graylog.

### Backup Strategy

1. **Autonomi Network Data**:
   - Data stored on the Autonomi network is automatically replicated
   - Regular backups of storage keys and wallet keys are recommended

2. **Configuration Data**:
   - Back up the `.env` file and custom configurations
   - Version control for configuration changes

3. **Redis Data**:
   - Configure Redis persistence (RDB or AOF)
   - Schedule regular Redis snapshots

4. **SSL Certificates**:
   - Back up the contents of `certbot/conf/`

Backup script example:

```bash
#!/bin/bash
# backup.sh - Backup script for AutonomAuth

BACKUP_DIR="/path/to/backups"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
BACKUP_FILE="$BACKUP_DIR/autonomauth_backup_$TIMESTAMP.tar.gz"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Stop containers to ensure consistent state
docker-compose stop redis

# Create backup archive
tar -czf "$BACKUP_FILE" \
  .env \
  nginx/conf.d/ \
  certbot/conf/ \
  data/redis/

# Restart containers
docker-compose start redis

echo "Backup created at $BACKUP_FILE"
```

### SSL Certificate Renewal

SSL certificates from Let's Encrypt are automatically renewed by the Certbot container. The renewal process is scheduled to run every 12 hours as defined in the `docker-compose.yml` file:

```yaml
certbot:
  entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
```

Nginx is configured to reload its configuration after certificate renewal to apply the new certificates.

## Integration Guide

### Website Integration

#### Basic JavaScript Integration

```html
<script src="https://auth.example.com/js/autonomauth.min.js"></script>
<button id="auth-button">Sign in with AutonomAuth</button>

<script>
  const auth = new AutonomAuth({
    serviceUrl: 'https://yourwebsite.com',
    apiUrl: 'https://auth.example.com/api',
    onAuthenticated: (session) => {
      console.log('User authenticated:', session);
      // Store session token and redirect user
      localStorage.setItem('authSession', session.session_id);
      window.location.href = '/dashboard';
    },
    onError: (error) => {
      console.error('Authentication error:', error);
    }
  });
  
  document.getElementById('auth-button').addEventListener('click', () => {
    auth.showAuthWidget();
  });
</script>
```

#### React Integration

```jsx
import React from 'react';
import { AutonomAuth } from 'autonomauth-react';

function LoginPage() {
  const handleAuthenticated = (session) => {
    console.log('User authenticated:', session);
    // Store session token and redirect user
    localStorage.setItem('authSession', session.session_id);
    window.location.href = '/dashboard';
  };
  
  return (
    <div>
      <h1>Login</h1>
      <AutonomAuth
        serviceUrl="https://yourwebsite.com"
        apiUrl="https://auth.example.com/api"
        onAuthenticated={handleAuthenticated}
        theme="light"
      />
    </div>
  );
}

export default LoginPage;
```

### Mobile App Integration

For integrating with a React Native mobile app:

```jsx
import React from 'react';
import { View, Text, Button } from 'react-native';
import { useAutonomAuth } from 'react-native-autonomauth';

function AuthScreen() {
  const {
    userId,
    loading,
    error,
    profiles,
    createIdentity,
    authenticate,
  } = useAutonomAuth();
  
  const handleCreateIdentity = async () => {
    try {
      await createIdentity({
        use_mnemonic: false,
        testnet: true,
      });
      console.log('Identity created successfully');
    } catch (err) {
      console.error('Error creating identity:', err);
    }
  };
  
  const handleAuthenticate = async () => {
    if (profiles.length === 0) return;
    
    try {
      const result = await authenticate(profiles[0].id);
      console.log('Authentication successful:', result);
    } catch (err) {
      console.error('Authentication failed:', err);
    }
  };
  
  if (loading) return <Text>Loading...</Text>;
  
  return (
    <View>
      {!userId ? (
        <Button title="Create Identity" onPress={handleCreateIdentity} />
      ) : (
        <Button title="Authenticate" onPress={handleAuthenticate} />
      )}
    </View>
  );
}

export default AuthScreen;
```

### Backend Verification

To verify authentication on your backend:

```javascript
// Node.js example using axios
const axios = require('axios');

async function verifySession(sessionId) {
  try {
    const response = await axios.post('https://auth.example.com/api/sessions/verify', {
      session_id: sessionId
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const { valid, profile_id, remaining_seconds } = response.data;
    
    if (valid) {
      // Session is valid
      return {
        valid: true,
        profileId: profile_id,
        expiresIn: remaining_seconds
      };
    } else {
      // Session is invalid
      return { valid: false };
    }
  } catch (error) {
    console.error('Session verification error:', error);
    return { valid: false, error: error.message };
  }
}
```

## Security Considerations

### Key Management

- **Master Key**: Never transmitted over the network, stays on user's device
- **Storage Key**: Used for Autonomi network access, must be securely stored
- **Wallet Key**: Used for payments, must be securely stored

Recommended key storage methods:

- **Mobile App**: Use secure enclave or keystore
- **Server**: Use HashiCorp Vault or AWS KMS

### Network Security

- **TLS/SSL**: All communications secured with TLS 1.2+
- **HSTS**: Strict Transport Security enabled
- **CSP**: Content Security Policy to prevent XSS
- **Rate Limiting**: Prevent brute force attacks
- **IP Filtering**: Optional IP-based access restrictions for admin endpoints

### API Security

- **Input Validation**: All inputs validated on both client and server
- **CSRF Protection**: Cross-Site Request Forgery protection
- **Rate Limiting**: API rate limiting on all endpoints
- **Security Headers**: Comprehensive security headers
- **Error Handling**: Secure error handling without information leakage

### Authentication Service Hardening

1. **OS Hardening**:
   - Use minimal base images
   - Regular security updates
   - Remove unnecessary services

2. **Service Isolation**:
   - Each service runs in its own container
   - Principle of least privilege

3. **Docker Security**:
   - Read-only file systems where possible
   - Drop capabilities
   - Resource limitations

4. **Secret Management**:
   - Use environment variables or dedicated secret management
   - Avoid hard-coded credentials

5. **Regular Security Scans**:
   - Container vulnerability scanning
   - Dependency scanning
   - Static code analysis

### Implementation Recommendations

- **Use SecOps Tools**: Integrate security scanning in CI/CD pipeline
- **Regular Audits**: Conduct regular security audits
- **Update Dependencies**: Keep all dependencies up to date
- **Monitor Logs**: Set up alerts for suspicious activities
- **Penetration Testing**: Regular penetration testing

## Troubleshooting

### Common Issues and Solutions

#### Connection to Autonomi Network Fails

**Symptoms**: Auth service logs show connection errors, uploads fail

**Possible causes**:
- Autonomi client not running
- Insufficient ANT tokens
- Network connectivity issues

**Solutions**:
1. Check Autonomi client status:
   ```bash
   docker-compose logs autonomi-client
   ```
2. Verify wallet has sufficient ANT tokens
3. Check network configuration and firewall rules

#### SSL Certificate Issues

**Symptoms**: Browser shows certificate warnings, SSL handshake failures

**Possible causes**:
- Certificate not yet provisioned
- Domain mismatch
- Certificate expired

**Solutions**:
1. Check certificate status:
   ```bash
   docker-compose exec certbot certbot certificates
   ```
2. Verify domain configuration in `.env` file
3. Force certificate renewal:
   ```bash
   docker-compose exec certbot certbot renew --force-renewal
   ```
4. Restart Nginx:
   ```bash
   docker-compose restart nginx
   ```

#### Authentication Challenges Expire Too Quickly

**Symptoms**: Users report authentication failures, QR codes expiring before they can be scanned

**Possible causes**:
- Challenge expiry time too short
- Clock synchronization issues
- High network latency

**Solutions**:
1. Increase challenge expiry time in API configuration
2. Synchronize server time with NTP
3. Check network latency between services

#### Push Notifications Not Delivered

**Symptoms**: Mobile app doesn't receive push notifications for authentication requests

**Possible causes**:
- Firebase credentials misconfigured
- Mobile app not registered for notifications
- Firebase token expired

**Solutions**:
1. Verify Firebase credentials
2. Check device registration status in logs
3. Re-register device for push notifications

#### Performance Issues

**Symptoms**: Slow response times, high CPU/memory usage

**Possible causes**:
- Insufficient resources
- Redis cache issue
- Database connection pool exhaustion

**Solutions**:
1. Scale services horizontally:
   ```bash
   docker-compose up -d --scale auth-service=3
   ```
2. Increase container resource limits in Docker Compose
3. Monitor performance metrics in Grafana

### Diagnostic Commands

#### Check Container Status

```bash
# List all containers and their status
docker-compose ps

# View container resources
docker stats
```

#### View Service Logs

```bash
# View logs for a specific service
docker-compose logs auth-service

# View logs with timestamps
docker-compose logs --timestamps nginx

# Follow logs in real-time
docker-compose logs -f challenge-service
```

#### Check Network Configuration

```bash
# Inspect network
docker network inspect autonomauth-network

# Test connectivity between services
docker-compose exec auth-service ping redis
```

#### Verify API Endpoints

```bash
# Test health check endpoint
curl -i https://auth.example.com/api/health

# Test API endpoint (replace with valid challenge ID)
curl -i https://auth.example.com/api/challenges/550e8400-e29b-41d4-a716-446655440000
```

### Getting Help

For additional support:

- **GitHub Issues**: Report bugs at https://github.com/yourusername/autonomauth/issues
- **Documentation**: Comprehensive documentation at https://docs.autonomauth.com
- **Community Forum**: Discuss with the community at https://forum.autonomauth.com
- **Email Support**: Contact support@autonomauth.com for critical issues

## Reference Materials

- **Autonomi Network Documentation**: https://docs.autonomi.com
- **Docker Documentation**: https://docs.docker.com
- **Nginx Documentation**: https://nginx.org/en/docs/
- **Let's Encrypt Documentation**: https://letsencrypt.org/docs/
- **React Native Documentation**: https://reactnative.dev/docs/getting-started

---

This implementation guide is continuously updated. For the latest version, please visit our documentation website.
