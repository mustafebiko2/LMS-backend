from flask import Flask, make_response, request
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_cors import CORS  # Import CORS
from models import db, User
import random
import string

# Initialize the flask application
app = Flask(__name__)

# Configure CORS
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins; you can restrict this to specific domains

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "super-secret"

# Configure mail for password reset
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Replace with your actual Gmail address
app.config['MAIL_PASSWORD'] = 'your_app_password'      # Replace with your actual App Password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
db.init_app(app)
api = Api(app)

class Users(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        print(current_user)
        users = User.query.all()
        users_list = [user.to_dict() for user in users]
        body = {
            "count": len(users_list),
            "users": users_list
        }
        return make_response(body, 200)

    def post(self):
        email = User.query.filter_by(email=request.json.get('email')).first()
        if email:
            return make_response({"message": "Email already taken"}, 422)

        new_user = User(
            username=request.json.get("username"),
            email=request.json.get("email"),
            role="user",  # Default role for new users
            password=bcrypt.generate_password_hash(request.json.get("password"))
        )

        db.session.add(new_user)
        db.session.commit()

        access_token = create_access_token(identity=new_user.id)
        response = {
            "user": new_user.to_dict(),
            "access_token": access_token
        }
        return make_response(response, 201)

class Login(Resource):
    def post(self):
        email = request.json.get('email')
        password = request.json.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id)
            return make_response({
                "user": user.to_dict(),
                "access_token": access_token
            }, 200)
        return make_response({"message": "Invalid credentials"}, 401)

api.add_resource(Users, '/users')
api.add_resource(Login, '/login')

if __name__ == '__main__':
    app.run(debug=True)
