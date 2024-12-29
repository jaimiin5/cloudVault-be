from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import datetime
import os
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity,create_access_token

app = Flask(__name__)

CORS(app)
SECRET_KEY = "askdno02i2b3kj"

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:root@localhost/postgres"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "docx", "rar", "webm"}

# jwt token
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your_secret_key")
jwt = JWTManager(app)


def generate_jwt(username):
    return create_access_token(identity=username, expires_delta=datetime.timedelta(hours=1))

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Create the necessary directories
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# Models
class User(db.Model):
    __tablename__ = "userdata"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)

    files = db.relationship("File", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class File(db.Model):
    __tablename__ = "files"

    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("userdata.id"), nullable=False)
    filename = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    uploaded_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<File {self.filename}>"


# Helper function to generate JWT
# def generate_jwt(username):
#     payload = {
#         "username": username,
#         "exp": datetime.datetime.now(datetime.timezone.utc)
#         + datetime.timedelta(hours=1),  # Use timezone-aware UTC time
#     }
#     return create_access_token(identity=username, expires_delta=datetime.timedelta(hours=1))

#     return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# Helper function to check allowed file extensions
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# Routes
@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return (
                jsonify({"error": f"{username} already exists! Try logging in."}),
                400,
            )

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        token = generate_jwt(username)
        print('asa?????????',token)
        return (
            jsonify(
                {
                    "token": token,
                    "message": "Registration successful!",
                    "user_id": new_user.id,
                }
            ),
            201,
        )
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login():

    try:

        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        print(username, password)

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        user = User.query.filter(User.username == username).first()
        print(user)

        if user and user.password == password:
            token = generate_jwt(username)
            return (
                jsonify(
                    {"token": token, "message": "Login successful!", "user_id": user.id}
                ),
                201,
            )

        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"message": str(e)}), 500


# this is for all files available in backend
@app.route("/api/read", methods=["GET"])
def get_data():
    users = User.query.all()
    return jsonify(
        {"data": [{"id": user.id, "username": user.username} for user in users]}
    )


@app.route("/api/user/<int:active_user_id>", methods=["GET"])
def get_active_data(active_user_id):
    user = User.query.get(active_user_id)
    if user:
        return jsonify({"data": {"id": user.id, "username": user.username}})
    else:
        return jsonify({"message": "User not found"}), 404


@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400

    user_id = request.form.get("activeUserId")
    if not user_id:
        return jsonify({"message": "User ID is required. Log in again."}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        new_file = File(user_id=user_id, filename=filename, file_path=file_path)
        db.session.add(new_file)
        db.session.commit()

        return (
            jsonify({"message": "File uploaded successfully!", "file_path": file_path}),
            200,
        )
    else:
        return jsonify({"message": "File type not allowed"}), 400


@app.route("/api/files/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user_files(user_id):

    current_user = get_jwt_identity()
    #jwt will get username by token


    #this is from db
    user = User.query.filter_by(id=user_id).first()

    #check if username is exist
    if current_user != user.username:
        return jsonify({"message": "Unauthorized access"}), 403

    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 10, type=int)

    if limit > 50:
        return jsonify({"message": "Limit cannot be greater than 100"}), 400

    # files_query = File.query.filter_by(user_id=user_id).paginate(page, limit, False)
    files_query = File.query.filter_by(user_id=user_id).paginate(
        page=page, per_page=limit, error_out=False
    )

    files_data = [
        {
            "user_id": file.user_id,
            "filename": file.filename,
            "file_path": file.file_path,
            "date": file.uploaded_at,
            "file_id": file.file_id,
        }
        for file in files_query.items
    ]
    return jsonify(
        {"files": files_data, "page": page, "limit": limit, "length": files_query.total}
    )


@app.route("/api/files/delete/<int:file_id>", methods=["DELETE"])
def delete_file(file_id):
    file = File.query.get(file_id)
    if file:
        db.session.delete(file)
        db.session.commit()
        return jsonify({"message": "File deleted successfully!"}), 202
    else:
        return jsonify({"message": "File not found"}), 404


@app.route("/static/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(os.path.join("static", "uploads"), filename)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Creates tables from models
    app.run(debug=True)
