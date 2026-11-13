# Authentication & User Management API

Endpoints for user authentication, token renewal, session management, and role-based access control.

---

## 1. Login

Authenticate with user credentials to receive a JWT access token and refresh token.

- **Endpoint**: `POST /auth/login`
- **Auth**: None
- **Rate Limit**: 10 requests / minute

### Request Body

```json
{
  "email": "analyst@example.com",
  "password": "SecurePassword123!"
}
```

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer",
    "expires_in": 900,
    "user": {
      "id": "11111111-1111-1111-1111-111111111111",
      "email": "analyst@example.com",
      "username": "soc_analyst_1",
      "display_name": "SOC Lead",
      "role": "analyst",
      "organization_id": "22222222-2222-2222-2222-222222222222"
    }
  },
  "error": null
}
```

---

## 2. Refresh Token

Exchange a valid refresh token for a fresh access token. Uses refresh token rotation.

- **Endpoint**: `POST /auth/refresh`
- **Auth**: None

### Request Body

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsIn..."
}
```

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer",
    "expires_in": 900
  },
  "error": null
}
```

---

## 3. Current User Profile

Get details of the currently authenticated analyst.

- **Endpoint**: `GET /auth/me`
- **Auth**: Bearer token

### Response (`200 OK`)

```json
{
  "success": true,
  "data": {
    "id": "11111111-1111-1111-1111-111111111111",
    "email": "analyst@example.com",
    "username": "soc_analyst_1",
    "display_name": "SOC Lead",
    "role": "analyst",
    "organization_id": "22222222-2222-2222-2222-222222222222",
    "organization": {
      "id": "22222222-2222-2222-2222-222222222222",
      "name": "SOC Alpha",
      "plan": "enterprise"
    }
  },
  "error": null
}
```

---

## 4. User Administration (`security_admin` & `super_admin`)

- **List Users**: `GET /users?page=1&page_size=20`
- **Create User**: `POST /users`
- **Update Role/Status**: `PATCH /users/{user_id}`
- **Delete User**: `DELETE /users/{user_id}`
