from flask import Flask, request, make_response, render_template, redirect
import jwt
import datetime

app = Flask(__name__)
app.secret_key = "clave-secreta"

# Generar un token JWT
def generate_jwt(payload):
    token = jwt.encode(
        {**payload, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        app.secret_key,
        algorithm="HS256"
    )
    return token

# Validar y decodificar un token JWT
def decode_jwt(token):
    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return None  # Token expirado
    except jwt.InvalidTokenError:
        return None  # Token inválido

@app.route("/")
def ola():
    return render_template('index.html')

@app.route("/admin", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.values.get('username')
        password = request.values.get('password')

        if username == "admin" and password == "admin":
            payload = {"username": username, "admin": True}
            token = generate_jwt(payload)
            
            resp = make_response(redirect("/user"))
            resp.set_cookie("sessionId", token, httponly=True, secure=True, samesite='Strict')
            return resp
        else:
            return redirect("/admin")
    else:
        return render_template('admin.html')

@app.route("/user", methods=['GET'])
def userInfo():
    token = request.cookies.get("sessionId")
    if not token:
        return "Não Autorizado!"
    
    decoded = decode_jwt(token)
    if not decoded or not decoded.get("admin"):
        return "Não Autorizado!"
    
    return render_template('user.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
