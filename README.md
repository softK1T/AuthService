# AuthService

A modern ASP.NET Core 9.0 authentication microservice with JWT tokens, email confirmation, and role-based authorization.

## 🚀 Quick Start

### Prerequisites
- .NET 9.0 SDK
- SQL Server or PostgreSQL
- Email service endpoint

### Setup
```bash
# Clone and restore packages
git clone <repository-url>
cd AuthService
dotnet restore

# Configure database connection in appsettings.json
# Run migrations
dotnet ef database update

# Start the service
dotnet run
```

### API Endpoints
- `POST /api/auth/register` - Register new user
- `GET /api/auth/confirm-email` - Confirm email address  
- `POST /api/auth/login` - Authenticate user

## 🔧 Configuration

### Required Environment Variables
```bash
DB_CONNECTION_STRING=your-database-connection
JWT_KEY=your-256-bit-secret-key
JWT_ISSUER=AuthService
JWT_AUDIENCE=AuthServiceClients
MAIL_SERVICE_URL=https://your-mail-service
```

## 🐳 Docker

```bash
# Build image
docker build -t authservice .

# Run container
docker run -p 5000:80 \
  -e DB_CONNECTION_STRING="your-connection-string" \
  -e JWT_KEY="your-secret-key" \
  authservice
```

## 📚 Documentation

See [complete documentation](authservice-documentation.md) for detailed setup, API reference, and deployment guides.

## 🔑 Key Features

- **JWT Authentication** - Stateless token-based auth
- **Email Confirmation** - Secure account verification
- **Role Management** - User/Admin role support
- **Multi-Database** - SQL Server & PostgreSQL support
- **Container Ready** - Docker deployment support
- **API Documentation** - Built-in Swagger UI

## 🛡️ Security

- Strong password requirements (8+ chars, digits, uppercase)
- Email confirmation required before login
- JWT tokens with configurable expiration
- Role-based authorization
- Secure token validation

## 📖 API Usage Examples

### Register User
```bash
curl -X POST https://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com", 
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Login
```bash
curl -X POST https://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

## 🏗️ Architecture

- **Controllers**: API endpoints and request handling
- **Services**: Business logic (JWT, Email)
- **Models**: Data entities and DTOs
- **Data**: Entity Framework context and migrations

