
README_API.md - Setup & Testing
-------------------------------
Requirements:
- Python 3.8+
- pip install flask pyjwt werkzeug cryptography

Run API:
1) (optional) export SECURE_API_SECRET="a-very-strong-secret-32+chars"
2) python secure_api.py

Example curl flows:
- Register:
  curl -X POST http://127.0.0.1:5000/register -H "Content-Type: application/json" -d '{"username":"alice","password":"S3curePassw0rd!"}'

- Login:
  curl -X POST http://127.0.0.1:5000/login -H "Content-Type: application/json" -d '{"username":"alice","password":"S3curePassw0rd!"}'

- Protected profile (replace <TOKEN> with the access_token from login):
  curl -X GET http://127.0.0.1:5000/profile -H "Authorization: Bearer <TOKEN>"
