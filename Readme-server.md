| Endpoint      | Method | Input                                      | Response                                  | Description                                      |
|---------------|--------|--------------------------------------------|-------------------------------------------|--------------------------------------------------|
| /login        | POST   | `{ "username": string, "password": string }` | `{ "token": string }`                       | Authenticates user, generates JWT token if valid credentials. |
| /register     | POST   | `{ "username": string, "password": string }` | `{ "message": string }`                     | Registers a new user.                           |
| /protected    | GET    | -                                          | `{ "message": string }`                     | Accesses a protected route using JWT token.     |
