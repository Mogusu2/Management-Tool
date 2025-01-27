from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
import bcrypt
from dotenv import load_dotenv
from datetime import timedelta
import os
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Database configuration
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "port": os.getenv("DB_PORT"),
}
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}"

# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mallow = Marshmallow(app)

# Models
class Role(db.Model):
    __tablename__ = "role"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    members = db.relationship('Member', back_populates="role")

class Member(db.Model):
    __tablename__ = "member"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    role = db.relationship("Role", back_populates="members")

class Budget(db.Model):
    __tablename__ = "budget"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)

    invoices = db.relationship("Invoice", back_populates="budget")

class Expense(db.Model):
    __tablename__ = "expense"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String(250), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    budget_id = db.Column(db.Integer, db.ForeignKey('budget.id', ondelete='CASCADE'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id', ondelete='CASCADE'), nullable=False)

class Invoice(db.Model):
    __tablename__ = "invoice"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    number = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    amount = db.Column(db.Float, nullable=False)
    budget_id = db.Column(db.Integer, db.ForeignKey("budget.id"), nullable=False)

    budget = db.relationship("Budget", back_populates="invoices")


# Schemas
class RoleSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Role
        include_relationships = True
        load_instance = True

class MemberSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Member
        include_fk = True
        load_instance = True

class BudgetSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Budget
        include_fk = True
        load_instance = True

class ExpenseSchema(mallow.SQLAlchemyAutoSchema):
    class Meta:
        model = Expense
        include_fk = True
        load_instance = True

member_schema = MemberSchema()
members_schema = MemberSchema(many=True)
budget_schema = BudgetSchema()
budgets_schema = BudgetSchema(many=True)
expense_schema = ExpenseSchema()
expenses_schema = ExpenseSchema(many=True)

# Routes
@app.route("/sign-up", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    role_id = data.get('role_id')
    password = data.get('password')

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    new_member = Member(name=name, email=email, role_id=role_id, password=hashed.decode('utf8'))
    db.session.add(new_member)
    db.session.commit()

    return jsonify({"message": "Sign-up successful"})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    member = Member.query.filter_by(email=email).first()

    if not member or not bcrypt.checkpw(password.encode('utf-8'), member.password.encode('utf-8')):
        return jsonify({"message": "Invalid email or password"}), 400

    access_token = create_access_token(identity=member.id, expires_delta=timedelta(days=1))
    return jsonify({"message": f"Welcome {member.name}", "access_token": access_token})

@app.route("/budgets", methods=["POST"])
@jwt_required()
def create_budget():
    data = request.get_json()
    current_user = get_jwt_identity()
    new_budget = Budget(name=data['name'], amount=data['amount'], member_id=current_user)
    db.session.add(new_budget)
    db.session.commit()
    return budget_schema.jsonify(new_budget)

@app.route("/expenses", methods=["POST"])
@jwt_required()
def log_expense():
    data = request.get_json()
    current_user = get_jwt_identity()
    new_expense = Expense(description=data['description'], amount=data['amount'], budget_id=data['budget_id'], member_id=current_user)
    db.session.add(new_expense)
    db.session.commit()
    return expense_schema.jsonify(new_expense)

@app.route("/invoices", methods=["POST"])
@jwt_required()
def create_invoice():
    data = request.get_json()
    budget_id = data.get("budget_id")
    amount = data.get("amount")

    # Validate budget exists
    budget = Budget.query.get(budget_id)
    if not budget:
        return jsonify({"message": "Budget not found"}), 404

    # Generate invoice number
    invoice_number = f"INV-{uuid.uuid4().hex[:8].upper()}"

    new_invoice = Invoice(number=invoice_number, amount=amount, budget_id=budget_id)
    db.session.add(new_invoice)
    db.session.commit()

    return jsonify({"message": "Invoice created", "invoice": invoice_number})


@app.route("/reports/budget-utilization", methods=["GET"])
@jwt_required()
def budget_utilization():
    # Aggregate data
    budgets = Budget.query.all()
    report = [
        {"name": b.name, "utilized": sum(e.amount for e in b.expenses), "total": b.amount}
        for b in budgets
    ]

    return jsonify({"report": report})



if __name__ == '__main__':
    app.run(debug=True)
