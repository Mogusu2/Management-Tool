from flask import Flask, jsonify, request, send_file
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
)
from flask_cors import CORS
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import base64
import os
import uuid
import json
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
import paypalrestsdk
from paypalrestsdk import Payment as PayPalPayment

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"])



# Database Configuration
# DATABASE_URL is set using environment variables in the app.config

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@"
    f"{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#print(f"Database URL: postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}")



# JWT Configuration
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# Email Configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("EMAIL_USER")
app.config["MAIL_PASSWORD"] = os.getenv("EMAIL_PASS")

# PayPal Configuration
paypalrestsdk.configure({
    'mode': 'sandbox',  # or 'live' for production
    'client_id': os.environ.get('PAYPAL_CLIENT_ID'),
    'client_secret': os.environ.get('PAYPAL_CLIENT_SECRET')
})

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)
jwt = JWTManager(app)
mail = Mail(app)

# Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

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
    budgets = db.relationship("Budget", backref="user", lazy=True)
    expenses = db.relationship("Expense", backref="user", lazy=True)
    invoices = db.relationship("Invoice", backref="user", lazy=True)

class Budget(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    monthly_limit = db.Column(db.Float, nullable=False)
    current_spending = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    expenses = db.relationship("Expense", backref="budget", lazy=True)

class Expense(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    budget_id = db.Column(db.String(36), db.ForeignKey("budget.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Invoice(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("user.id"), nullable=False)
    client_name = db.Column(db.String(100), nullable=False)
    client_email = db.Column(db.String(120), nullable=False)
    items = db.Column(db.JSON, nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Payment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    invoice_id = db.Column(db.String(36), db.ForeignKey("invoice.id"), nullable=False)
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
        exclude = ("password",)

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

user_schema = UserSchema()
budget_schema = BudgetSchema()
expense_schema = ExpenseSchema()
invoice_schema = InvoiceSchema()
payment_schema = PaymentSchema()

# --------------------------
# Decorators
# --------------------------

def role_required(roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user["role"] not in roles:
                return jsonify({"message": "Unauthorized access"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# --------------------------
# Authentication Routes
# --------------------------

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    required_fields = ["username", "email", "password", "role"]
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    if User.query.filter_by(username=data["username"]).first():
        return jsonify({"message": "Username already exists"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"message": "Email already exists"}), 400

    hashed_password = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt())
    
    new_user = User(
        id=str(uuid.uuid4()),
        username=data["username"],
        email=data["email"],
        password=hashed_password.decode("utf-8"),
        role=data["role"]
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify(user_schema.dump(new_user)), 201

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()

    if not user or not bcrypt.checkpw(data["password"].encode("utf-8"), user.password.encode("utf-8")):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity={
        "id": user.id,
        "username": user.username,
        "role": user.role
    })
    
    return jsonify(access_token=access_token), 200

# --------------------------
# Budget Routes
# --------------------------

@app.route("/budgets", methods=["GET", "POST"])
@jwt_required()
def manage_budgets():
    current_user = get_jwt_identity()
    
    if request.method == "GET":
        budgets = Budget.query.filter_by(user_id=current_user["id"]).all()
        return jsonify(budget_schema.dump(budgets, many=True)), 200
    
    if request.method == "POST":
        data = request.get_json()
        new_budget = Budget(
            id=str(uuid.uuid4()),
            user_id=current_user["id"],
            category=data["category"],
            monthly_limit=data["monthly_limit"]
        )
        db.session.add(new_budget)
        db.session.commit()
        return jsonify(budget_schema.dump(new_budget)), 201

# --------------------------
# Expense Routes
# --------------------------

@app.route("/expenses", methods=["GET", "POST"])
@jwt_required()
def manage_expenses():
    current_user = get_jwt_identity()
    
    if request.method == "GET":
        expenses = Expense.query.filter_by(user_id=current_user["id"]).all()
        return jsonify(expense_schema.dump(expenses, many=True)), 200
    
    if request.method == "POST":
        data = request.get_json()
        budget = Budget.query.get(data["budget_id"])
        
        if not budget or budget.user_id != current_user["id"]:
            return jsonify({"message": "Budget not found"}), 404
            
        new_expense = Expense(
            id=str(uuid.uuid4()),
            user_id=current_user["id"],
            budget_id=budget.id,
            amount=data["amount"],
            description=data.get("description")
        )
        
        budget.current_spending += data["amount"]
        db.session.add(new_expense)
        db.session.commit()
        return jsonify(expense_schema.dump(new_expense)), 201

@app.route("/expenses/<expense_id>", methods=["DELETE"])
@jwt_required()
def delete_expense(expense_id):
    current_user = get_jwt_identity()
    expense = Expense.query.get(expense_id)
    
    if not expense or expense.user_id != current_user["id"]:
        return jsonify({"message": "Expense not found"}), 404
    
    budget = Budget.query.get(expense.budget_id)
    budget.current_spending -= expense.amount
    
    db.session.delete(expense)
    db.session.commit()
    return jsonify({"message": "Expense deleted"}), 200

# --------------------------
# Invoice Routes
# --------------------------

def generate_invoice_pdf(invoice):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    elements = []
    elements.append(Paragraph(f"Invoice #{invoice.id}", styles["Title"]))
    elements.append(Paragraph(f"Date: {invoice.created_at.date()}", styles["Normal"]))
    elements.append(Paragraph(f"Client: {invoice.client_name}", styles["Normal"]))
    elements.append(Paragraph(f"Client Email: {invoice.client_email}", styles["Normal"]))
    
    # Create items table
    data = [["Description", "Amount"]]
    for item in invoice.items:
        data.append([item["description"], f"${item['amount']}"])
    
    table = Table(data)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), "#CCCCCC"),
        ("TEXTCOLOR", (0,0), (-1,0), "#000000"),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("FONTSIZE", (0,0), (-1,0), 12),
        ("BOTTOMPADDING", (0,0), (-1,0), 12),
        ("BACKGROUND", (0,1), (-1,-1), "#FFFFFF"),
        ("GRID", (0,0), (-1,-1), 1, "#000000")
    ]))
    
    elements.append(table)
    elements.append(Paragraph(f"Total: ${invoice.total}", styles["Heading2"]))
    elements.append(Paragraph(f"Status: {invoice.status}", styles["Normal"]))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

@app.route("/invoices", methods=["POST"])
@jwt_required()
def create_invoice():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    total = sum(item["amount"] for item in data["items"])
    user = User.query.get(current_user["id"])
    
    new_invoice = Invoice(
        id=str(uuid.uuid4()),
        user_id=current_user["id"],
        client_name=data["client_name"],
        client_email=data["client_email"],
        items=data["items"],
        total=total
    )
    
    db.session.add(new_invoice)
    db.session.commit()
    
    # Generate PDF
    pdf_buffer = generate_invoice_pdf(new_invoice)
    
    # Send email
    msg = Message(
        subject=f"Invoice #{new_invoice.id} from {user.username}",
        sender=user.email,
        recipients=[new_invoice.client_email]
    )
    msg.body = f"Please find attached invoice #{new_invoice.id}"
    msg.attach("invoice.pdf", "application/pdf", pdf_buffer.getvalue())
    mail.send(msg)
    
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        download_name=f"invoice_{new_invoice.id}.pdf"
    )

# --------------------------
# Report Routes
# --------------------------

@app.route("/reports", methods=["GET"])
@jwt_required()
def generate_report():
    current_user = get_jwt_identity()
    user = User.query.get(current_user["id"])
    
    # Get filters
    category = request.args.get("category")
    timeframe = int(request.args.get("timeframe", 30))
    
    query = Expense.query.filter_by(user_id=user.id)
    
    if category:
        query = query.join(Budget).filter(Budget.category == category)
    
    if timeframe:
        start_date = datetime.utcnow() - timedelta(days=timeframe)
        query = query.filter(Expense.created_at >= start_date)
    
    expenses = query.all()
    
    # Generate PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    elements = []
    elements.append(Paragraph(f"Expense Report for {user.username}", styles["Title"]))
    elements.append(Paragraph(f"Period: Last {timeframe} days", styles["Normal"]))
    
    # Category summary
    category_totals = {}
    for expense in expenses:
        category = expense.budget.category
        category_totals[category] = category_totals.get(category, 0) + expense.amount
    
    category_data = [["Category", "Total"]]
    for cat, total in category_totals.items():
        category_data.append([cat, f"${total}"])
    
    category_table = Table(category_data)
    category_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), "#CCCCCC"),
        ("TEXTCOLOR", (0,0), (-1,0), "#000000"),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("GRID", (0,0), (-1,-1), 1, "#000000")
    ]))
    
    elements.append(category_table)
    
    # Detailed expenses
    elements.append(Paragraph("Transaction Details", styles["Heading2"]))
    transaction_data = [["Date", "Category", "Amount", "Description"]]
    for expense in expenses:
        transaction_data.append([
            expense.created_at.date(),
            expense.budget.category,
            f"${expense.amount}",
            expense.description or ""
        ])
    
    transaction_table = Table(transaction_data)
    transaction_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), "#EEEEEE"),
        ("TEXTCOLOR", (0,0), (-1,0), "#000000"),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("GRID", (0,0), (-1,-1), 1, "#AAAAAA")
    ]))
    
    elements.append(transaction_table)
    
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        download_name="expense_report.pdf"
    )

# --------------------------
# Payment Routes
# --------------------------

@app.route("/payments/paypal", methods=["POST"])
@jwt_required()
def initiate_paypal_payment():
    data = request.get_json()
    invoice = Invoice.query.get(data["invoice_id"])
    
    if not invoice or invoice.user_id != get_jwt_identity()["id"]:
        return jsonify({"message": "Invoice not found"}), 404
    
    payment = PayPalPayment({
        "intent": "sale",
        "payer": {"payment_method": "paypal"},
        "transactions": [{
            "amount": {
                "total": str(invoice.total),
                "currency": "USD"
            },
            "description": f"Invoice #{invoice.id}",
            "invoice_number": invoice.id
        }],
        "redirect_urls": {
            "return_url": f"{os.getenv('APP_URL')}/payments/paypal/success",
            "cancel_url": f"{os.getenv('APP_URL')}/payments/paypal/cancel"
        }
    })
    
    if payment.create():
        return jsonify({"approval_url": payment.links[1].href})
    return jsonify({"error": payment.error}), 500


@app.route("/payments/paypal/success", methods=["GET"])
def paypal_success():
    payment_id = request.args.get("paymentId")
    payer_id = request.args.get("PayerID")
    
    if not payment_id or not payer_id:
        return jsonify({"message": "Invalid payment details"}), 400
    
    payment = PayPalPayment.find(payment_id)
    
    if payment.execute({"payer_id": payer_id}):
        # Mark the invoice as paid in the database
        invoice_id = payment.transactions[0].invoice_number
        invoice = Invoice.query.get(invoice_id)
        if invoice:
            invoice.is_paid = True
            db.session.commit()
        return jsonify({"message": "Payment successful", "invoice_id": invoice_id}), 200
    return jsonify({"message": "Payment execution failed"}), 500


@app.route("/payments/paypal/cancel", methods=["GET"])
def paypal_cancel():
    return jsonify({"message": "Payment cancelled by the user"}), 200


# --------------------------
# M-Pesa Payment Routes
# --------------------------

def generate_mpesa_password():
    shortcode = os.getenv("MPESA_SHORTCODE")
    passkey = os.getenv("MPESA_PASSKEY")
    timestamp = generate_mpesa_timestamp()
    data_to_encode = shortcode + passkey + timestamp
    encoded_string = base64.b64encode(data_to_encode.encode("utf-8")).decode("utf-8")
    return encoded_string

def generate_mpesa_timestamp():
    return datetime.now().strftime("%Y%m%d%H%M%S")
def get_mpesa_access_token():
    consumer_key = os.getenv("MPESA_CONSUMER_KEY")
    consumer_secret = os.getenv("MPESA_CONSUMER_SECRET")
    api_url = os.getenv("MPESA_TOKEN_URL")
    response = requests.get(api_url, auth=(consumer_key, consumer_secret))
    if response.status_code == 200:
        return response.json()["access_token"]
    return None

@app.route("/payments/mpesa", methods=["POST"])
@app.route("/payments/mpesa", methods=["POST"])
@jwt_required()
def initiate_mpesa_payment():
    data = request.get_json()
    invoice = Invoice.query.get(data["invoice_id"])
    
    if not invoice or invoice.user_id != get_jwt_identity()["id"]:
        return jsonify({"message": "Invoice not found"}), 404
    
    # M-Pesa Payment Request Details
    payment_request = {
        "BusinessShortCode": os.getenv("MPESA_SHORTCODE"),
        "Password": generate_mpesa_password(),
        "Timestamp": generate_mpesa_timestamp(),
        "TransactionType": "CustomerPayBillOnline",
        "Amount": invoice.total,
        "PartyA": data["phone_number"],  # Customer's phone number
        "PartyB": os.getenv("MPESA_SHORTCODE"),
        "PhoneNumber": data["phone_number"],
        "CallBackURL": f"{os.getenv('APP_URL')}/payments/mpesa/callback",
        "AccountReference": f"Invoice-{invoice.id}",
        "TransactionDesc": f"Payment for Invoice #{invoice.id}"
    }
    
    # Make request to M-Pesa API
    response = requests.post(
        os.getenv("MPESA_API_URL"),
        headers={"Authorization": f"Bearer {get_mpesa_access_token()}"},
        json=payment_request
    )
    
    if response.status_code == 200:
        return jsonify({"message": "Payment initiated successfully"}), 200
    return jsonify({"error": response.json()}), response.status_code


@app.route("/payments/mpesa/callback", methods=["POST"])
def mpesa_callback():
    data = request.get_json()
    
    # Log the callback for debugging
    with open("mpesa_callback.log", "a") as log_file:
        log_file.write(f"{data}\n")
    
    result_code = data["Body"]["stkCallback"]["ResultCode"]
    result_desc = data["Body"]["stkCallback"]["ResultDesc"]
    invoice_id = data["Body"]["stkCallback"]["CallbackMetadata"]["Item"][0]["Value"]
    
    if result_code == 0:
        # Payment successful
        invoice = Invoice.query.get(invoice_id)
        if invoice:
            invoice.is_paid = True
            db.session.commit()
        return jsonify({"message": "Payment successful"}), 200
    else:
        # Payment failed or canceled
        return jsonify({"message": f"Payment failed: {result_desc}"}), 400





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