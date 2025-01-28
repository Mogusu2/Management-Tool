from flask import Flask, jsonify, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
import bcrypt
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps
import os
import uuid
from reportlab.pdfgen import canvas
from io import BytesIO

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure CORS for React app
CORS(app, origins=["http://localhost:3000"])

# Supabase PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)
jwt = JWTManager(app)

# --------------------------
# Database Models
# --------------------------

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, employee, freelancer
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    budgets = db.relationship('Budget', backref='user', lazy=True)
    expenses = db.relationship('Expense', backref='user', lazy=True)
    invoices = db.relationship('Invoice', backref='user', lazy=True)

class Budget(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    monthly_limit = db.Column(db.Float, nullable=False)
    current_spending = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expenses = db.relationship('Expense', backref='budget', lazy=True)

class Expense(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    budget_id = db.Column(db.String(36), db.ForeignKey('budget.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Invoice(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    client_name = db.Column(db.String(100), nullable=False)
    client_email = db.Column(db.String(120), nullable=False)
    items = db.Column(db.JSON, nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Payment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    invoice_id = db.Column(db.String(36), db.ForeignKey('invoice.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    method = db.Column(db.String(20), nullable=False)  # mpesa, paypal
    transaction_id = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

# --------------------------
# Marshmallow Schemas
# --------------------------

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        exclude = ('password',)

class BudgetSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Budget

class ExpenseSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Expense

class InvoiceSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Invoice

class PaymentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Payment

# Initialize schemas
user_schema = UserSchema()
budget_schema = BudgetSchema()
expense_schema = ExpenseSchema()
invoice_schema = InvoiceSchema()
payment_schema = PaymentSchema()

# --------------------------
# Utility Functions
# --------------------------

def role_required(roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user['role'] not in roles:
                return jsonify({"message": "Unauthorized access"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --------------------------
# Authentication Routes
# --------------------------

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already exists"}), 400

    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    
    new_user = User(
        id=str(uuid.uuid4()),
        username=data['username'],
        email=data['email'],
        password=hashed_password.decode('utf-8'),
        role=data['role']
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        "message": "User created successfully",
        "user": user_schema.dump(new_user)
    }), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        access_token = create_access_token(identity={
            'id': user.id,
            'username': user.username,
            'role': user.role
        })
        return jsonify(access_token=access_token), 200
        
    return jsonify({"message": "Invalid credentials"}), 401

# --------------------------
# Budget Routes
# --------------------------

@app.route('/budgets', methods=['GET', 'POST'])
@jwt_required()
def manage_budgets():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])
    
    if request.method == 'GET':
        budgets = Budget.query.filter_by(user_id=user.id).all()
        return jsonify(budget_schema.dump(budgets, many=True)), 200
    
    if request.method == 'POST':
        data = request.get_json()
        new_budget = Budget(
            id=str(uuid.uuid4()),
            user_id=user.id,
            category=data['category'],
            monthly_limit=data['monthly_limit']
        )
        db.session.add(new_budget)
        db.session.commit()
        return jsonify(budget_schema.dump(new_budget)), 201

# --------------------------
# Expense Routes
# --------------------------

@app.route('/expenses', methods=['GET', 'POST'])
@jwt_required()
def manage_expenses():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])
    
    if request.method == 'GET':
        expenses = Expense.query.filter_by(user_id=user.id).all()
        return jsonify(expense_schema.dump(expenses, many=True)), 200
    
    if request.method == 'POST':
        data = request.get_json()
        budget = Budget.query.get(data['budget_id'])
        
        if not budget:
            return jsonify({"message": "Budget not found"}), 404
            
        new_expense = Expense(
            id=str(uuid.uuid4()),
            user_id=user.id,
            budget_id=budget.id,
            amount=data['amount'],
            description=data.get('description')
        )
        
        budget.current_spending += data['amount']
        db.session.add(new_expense)
        db.session.commit()
        return jsonify(expense_schema.dump(new_expense)), 201

# --------------------------
# Invoice Routes
# --------------------------

@app.route('/invoices', methods=['POST'])
@jwt_required()
def create_invoice():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    total = sum(item['amount'] for item in data['items'])
    
    new_invoice = Invoice(
        id=str(uuid.uuid4()),
        user_id=current_user['id'],
        client_name=data['client_name'],
        client_email=data['client_email'],
        items=data['items'],
        total=total
    )
    
    db.session.add(new_invoice)
    db.session.commit()
    
    # Generate PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.drawString(100, 750, f"Invoice #{new_invoice.id}")
    p.drawString(100, 730, f"Client: {new_invoice.client_name}")
    y = 700
    for item in new_invoice.items:
        p.drawString(100, y, f"{item['description']}: ${item['amount']}")
        y -= 20
    p.drawString(100, y-20, f"Total: ${new_invoice.total}")
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', download_name=f"invoice_{new_invoice.id}.pdf")

# --------------------------
# Report Routes
# --------------------------

@app.route('/reports', methods=['GET'])
@jwt_required()
def generate_report():
    current_user = get_jwt_identity()
    user = User.query.get(current_user['id'])
    
    # Generate expense report
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.drawString(100, 750, f"Expense Report for {user.username}")
    y = 730
    for expense in user.expenses:
        p.drawString(100, y, f"{expense.created_at.date()} - {expense.budget.category}: ${expense.amount}")
        y -= 20
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf', download_name="expense_report.pdf")

# --------------------------
# Admin Routes
# --------------------------

@app.route('/admin/users', methods=['GET'])
@role_required(['admin'])
def get_all_users():
    users = User.query.all()
    return jsonify(user_schema.dump(users, many=True)), 200

# --------------------------
# Main Application
# --------------------------

if __name__ == '__main__':
    app.run(debug=True)