# AutonomAuth: Decentralized Authentication on Autonomi Network

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

AutonomAuth is a decentralized authentication system built on the [Autonomi Network](https://docs.autonomi.com) that gives users complete control over their identity and authentication data. It provides a secure, user-friendly alternative to traditional password-based authentication while ensuring that sensitive key material never leaves the user's device.

## Key Features

- **User-Controlled Identity**: All identity data stored on the decentralized Autonomi network
- **Multiple Identity Profiles**: Support for different identity profiles for different contexts
- **Challenge-Response Authentication**: Secure cryptographic authentication without passwords
- **QR Code and Push Notification**: Multiple authentication methods for different scenarios
- **WebAuthn/FIDO2 Integration**: Support for hardware security keys
- **Social Recovery**: Recover access through trusted guardians if a device is lost
- **Selective Disclosure**: Share only the information you want with services
- **Progressive Authentication**: Additional security for sensitive operations

## System Architecture

AutonomAuth uses a microservices architecture deployed with Docker Compose:

- **API Gateway**: Nginx with SSL termination and security headers
- **Auth Service**: Core authentication functionality
- **Challenge Service**: Manages authentication challenges
- **Session Service**: Handles authenticated sessions
- **Notification Service**: Sends push notifications to users
- **Supporting Services**: Redis, Prometheus, Grafana, and Autonomi Client

For details, see the [Implementation Guide](docs/implementation-guide.md).

## Installation

### Prerequisites

- Docker and Docker Compose
- Domain name (for production deployment)
- Autonomi Network access with ANT tokens
- ETH on Arbitrum for gas fees (production)

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/autonomauth.git
   cd autonomauth
   ```

2. Run the setup script:
   ```bash
   chmod +x scripts/setup.sh
   ./scripts/setup.sh
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Start the services:
   ```bash
   docker-compose up -d
   ```

For production deployment with SSL:
```bash
./scripts/init-letsencrypt.sh
```

## Usage

### For End Users

End users interact with AutonomAuth through:

1. **Mobile App**: For creating and managing identities, scanning QR codes, and approving authentication requests
2. **Browser Extensions**: For desktop authentication
3. **Website Widgets**: Displayed on websites that support AutonomAuth

See the [User Guide](docs/user-guide.md) for detailed instructions.

### For Developers

#### Website Integration

Add AutonomAuth to your website with our React component:

```jsx
import { AutonomAuth } from 'autonomauth-react';

function LoginPage() {
  const handleAuthenticated = (session) => {
    console.log('User authenticated:', session);
    // Store session token and redirect user
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
```

#### Backend Verification

Verify authentication on your backend:

```javascript
async function verifySession(sessionId) {
  const response = await fetch('https://auth.example.com/api/sessions/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId })
  });
  
  const data = await response.json();
  return data.valid;
}
```

For detailed integration instructions, see the [API Reference](docs/api-reference.md).

## Testing

A comprehensive test environment is provided for testing the authentication flow without implementing the full mobile app:

```bash
cd test-environment
docker-compose up -d
```

This starts a containerized test environment with:
- A web interface at http://localhost:8080
- A command-line testing tool
- Mock implementations of cryptographic operations

For details, see the [Test Environment Guide](docs/test-environment-guide.md).

## Project Structure

```
autonomauth/
├── src/                  # Core library
│   ├── crypto/           # Cryptographic functions
│   ├── storage/          # Storage implementations
│   ├── models/           # Data models
│   ├── error.rs          # Error handling
│   └── utils.rs          # Utilities
├── autonomauth-server/   # Server implementation
├── autonomauth-app/      # Mobile app core
├── autonomauth-web/      # Web components
├── test-environment/     # Testing tools
├── docs/                 # Documentation
└── deployment/           # Deployment configuration
```

## Documentation

- [User Guide](docs/user-guide.md) - For end users
- [Implementation Guide](docs/implementation-guide.md) - For system administrators
- [API Reference](docs/api-reference.md) - For developers
- [Test Environment Guide](docs/test-environment-guide.md) - For testing

## Security Considerations

AutonomAuth was designed with security as a primary concern:

- **Key Privacy**: Private keys never leave the user's device
- **End-to-End Encryption**: All communication is encrypted
- **Zero Knowledge**: Services only receive necessary information
- **Open Design**: Security through robust design, not obscurity
- **Regular Auditing**: Continuous security review process

For more details, see the security section in the [Implementation Guide](docs/implementation-guide.md#security-considerations).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

AutonomAuth is available under a dual licensing model:

### GNU General Public License v3.0

For open source projects, personal use, and community development, AutonomAuth is freely available under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0).

### Commercial License

For incorporating AutonomAuth into proprietary applications or products where the GPL-3.0 requirements cannot be satisfied, a commercial license is available. This allows you to integrate AutonomAuth without the source code disclosure requirements of GPL-3.0.

Contact [licensing@owlandabungeecord.com](mailto:licensing@owlandabungeecord.com) for commercial licensing terms and pricing.

## Acknowledgments

- [Autonomi Network](https://docs.autonomi.com) for providing the decentralized storage infrastructure
- [WebAuthn](https://www.w3.org/TR/webauthn-2/) for the web authentication standard
- All contributors to the project

## Contact

For questions or support, please open an issue on GitHub or contact us at [support@owlandabungeecord.com](mailto:support@owlandabungeecord.com).