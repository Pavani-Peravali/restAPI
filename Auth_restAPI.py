from flask import Flask
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key

api = Api(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Define the User model
class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Create tables
db.create_all()

# Resource to register a new user
class UserRegistration(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', help='This field cannot be blank', required=True)
        parser.add_argument('password', help='This field cannot be blank', required=True)
        data = parser.parse_args()

        if UserModel.query.filter_by(username=data['username']).first():
            return {'message': 'User {} already exists'.format(data['username'])}

        new_user = UserModel(
            username=data['username'],
            password=data['password']
        )
        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User {} created successfully'.format(data['username'])}

# Resource to get a JWT token
class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', help='This field cannot be blank', required=True)
        parser.add_argument('password', help='This field cannot be blank', required=True)
        data = parser.parse_args()

        current_user = UserModel.query.filter_by(username=data['username']).first()

        if not current_user:
            return {'message': 'User {} does not exist'.format(data['username'])}

        if data['password'] == current_user.password:
            access_token = create_access_token(identity=data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token
            }
        else:
            return {'message': 'Wrong credentials'}

# A resource that requires authentication
class InsertData(Resource):
    @jwt_required()
    def post(self):
        # This endpoint is protected, and only accessible with a valid JWT token
        parser = reqparse.RequestParser()
        parser.add_argument('data', help='This field cannot be blank', required=True)
        data = parser.parse_args()

        # Perform database insert or any other action here
        # For simplicity, we'll just print the data
        print(f"Data received: {data['data']}")

        return {'message': 'Data inserted successfully'}

api.add_resource(UserRegistration, '/registration')
api.add_resource(UserLogin, '/login')
api.add_resource(InsertData, '/insert-data')

if __name__ == '__main__':
    app.run(debug=True)
