import requests

# Test registration
response = requests.post('http://127.0.0.1:8000/api/register', json={
    "username": "test",
    "password": "Test123!",
    "email": "test@example.com"
})
print("Register:", response.status_code, response.text)

# Test login
response = requests.post('http://127.0.0.1:8000/api/login', json={
    "username": "test",
    "password": "Test123!"
}, allow_redirects=False)
print("Login:", response.status_code, response.text)
cookies = response.cookies

# If requires TOTP, but first time no
# Test setup TOTP
response = requests.post('http://127.0.0.1:8000/api/totp/setup', cookies=cookies)
print("Setup TOTP:", response.status_code)
if response.status_code == 200:
    data = response.json()
    print("TOTP secret:", data.get('secret'))
    print("QR code starts with:", data.get('qr_code')[:50])

# Test file encrypt
with open('test.txt', 'w') as f:
    f.write('Hello World')

files = {'file': open('test.txt', 'rb')}
data = {'password': 'secret'}
response = requests.post('http://127.0.0.1:8000/api/files/encrypt', files=files, data=data)
print("Encrypt:", response.status_code)
if response.status_code == 200:
    data = response.json()
    print("Encrypted file size:", len(data.get('encrypted_file', '')))
else:
    print("Error:", response.text)
