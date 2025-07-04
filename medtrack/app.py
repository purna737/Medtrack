from flask import Flask, render_template, request, redirect, url_for, session, flash
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from botocore.config import Config
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'

# DynamoDB Local Setup (region updated to us-east-1)
dynamodb = boto3.resource('dynamodb',
    region_name='us-east-1',
    endpoint_url='http://localhost:8000',
    aws_access_key_id='dummy',
    aws_secret_access_key='dummy',
    config=Config(signature_version='v4')
)

# Table names
TABLE_NAMES = {
    'users': 'MedTrackUsers',
    'appointments': 'MedTrackAppointments',
    'diagnoses': 'MedTrackDiagnoses',
    'metrics': 'MedTrackHealthMetrics'
}

# Auto-create DynamoDB tables
def ensure_tables():
    existing_tables = dynamodb.meta.client.list_tables()['TableNames']

    if TABLE_NAMES['users'] not in existing_tables:
        dynamodb.create_table(
            TableName=TABLE_NAMES['users'],
            KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'email', 'AttributeType': 'S'},
                {'AttributeName': 'role', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[{
                'IndexName': 'role-index',
                'KeySchema': [{'AttributeName': 'role', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            }],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

    if TABLE_NAMES['appointments'] not in existing_tables:
        dynamodb.create_table(
            TableName=TABLE_NAMES['appointments'],
            KeySchema=[{'AttributeName': 'appointment_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'appointment_id', 'AttributeType': 'S'},
                {'AttributeName': 'patient_id', 'AttributeType': 'S'},
                {'AttributeName': 'doctor_id', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'patient_id-index',
                    'KeySchema': [{'AttributeName': 'patient_id', 'KeyType': 'HASH'}],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                },
                {
                    'IndexName': 'doctor_id-index',
                    'KeySchema': [{'AttributeName': 'doctor_id', 'KeyType': 'HASH'}],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                }
            ],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

    if TABLE_NAMES['diagnoses'] not in existing_tables:
        dynamodb.create_table(
            TableName=TABLE_NAMES['diagnoses'],
            KeySchema=[{'AttributeName': 'diagnosis_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'diagnosis_id', 'AttributeType': 'S'},
                {'AttributeName': 'patient_id', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[{
                'IndexName': 'patient_id-index',
                'KeySchema': [{'AttributeName': 'patient_id', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            }],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

    if TABLE_NAMES['metrics'] not in existing_tables:
        dynamodb.create_table(
            TableName=TABLE_NAMES['metrics'],
            KeySchema=[{'AttributeName': 'metric_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'metric_id', 'AttributeType': 'S'},
                {'AttributeName': 'patient_id', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[{
                'IndexName': 'patient_id-index',
                'KeySchema': [{'AttributeName': 'patient_id', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            }],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )

ensure_tables()

# Table handles
users_table = dynamodb.Table(TABLE_NAMES['users'])
appointments_table = dynamodb.Table(TABLE_NAMES['appointments'])
diagnoses_table = dynamodb.Table(TABLE_NAMES['diagnoses'])
metrics_table = dynamodb.Table(TABLE_NAMES['metrics'])

# Helpers
def get_user_by_email(email):
    try:
        response = users_table.get_item(Key={'email': email})
        return response.get('Item')
    except Exception as e:
        print("Get User Error:", e)
        return None

def create_user(name, email, password_hash, role):
    try:
        users_table.put_item(Item={
            'user_id': str(uuid.uuid4()),
            'name': name,
            'email': email,
            'password_hash': password_hash,
            'role': role,
            'created_at': datetime.now().isoformat()
        })
        return True
    except Exception as e:
        print("Create User Error:", e)
        return False

def get_all_doctors():
    try:
        response = users_table.query(
            IndexName='role-index',
            KeyConditionExpression=Key('role').eq('doctor')
        )
        return response.get('Items', [])
    except Exception as e:
        print("Fetch doctors error:", e)
        return []

def get_appointments_for_patient(patient_id):
    try:
        response = appointments_table.query(
            IndexName='patient_id-index',
            KeyConditionExpression=Key('patient_id').eq(patient_id)
        )
        return response.get('Items', [])
    except Exception as e:
        print("Error getting appointments:", e)
        return []

def get_patient_details(patient_id):
    try:
        response = users_table.scan(
            FilterExpression=Key('user_id').eq(patient_id)
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        print("Error getting patient details:", e)
        return None

def get_health_metrics_for_patient(patient_id):
    try:
        response = metrics_table.query(
            IndexName='patient_id-index',
            KeyConditionExpression=Key('patient_id').eq(patient_id),
            Limit=3,
            ScanIndexForward=False
        )
        return response.get('Items', [])
    except Exception as e:
        print("Error fetching metrics:", e)
        return []

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        user = get_user_by_email(email)
        if not user or user['role'] != role or not check_password_hash(user['password_hash'], password):
            return "Invalid credentials", 401

        session.update({
            'logged_in': True,
            'user_id': user['user_id'],
            'user_name': user['name'],
            'user_role': user['role']
        })
        return redirect(url_for('patient_dashboard' if role == 'patient' else 'doctor_dashboard'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm-password']
        role = request.form.get('role', 'patient')
        terms = request.form.get('terms')

        if not terms:
            return "Please accept terms", 400
        if password != confirm:
            return "Passwords do not match", 400
        if get_user_by_email(email):
            return "Email already exists", 409

        hashed = generate_password_hash(password)
        if create_user(name, email, hashed, role):
            return redirect(url_for('login'))
        return "Signup failed", 500
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/appointment', methods=['GET', 'POST'])
def appointment():
    if not session.get('logged_in') or session['user_role'] != 'patient':
        return redirect(url_for('login'))

    doctors = get_all_doctors()

    if request.method == 'POST':
        data = {
            'appointment_id': str(uuid.uuid4()),
            'patient_id': session['user_id'],
            'doctor_id': request.form['doctor'],
            'appointment_date': request.form['appointment_date'],
            'appointment_time': request.form['appointment_time'],
            'reason': request.form['reason'] or 'General check-up',
            'status': 'Scheduled',
            'created_at': datetime.now().isoformat()
        }
        try:
            appointments_table.put_item(Item=data)
            return "Appointment booked successfully", 200
        except Exception as e:
            return f"Booking failed: {e}", 500

    return render_template('appointment.html', doctors=doctors)

@app.route('/patient_dashboard')
def patient_dashboard():
    if session.get('user_role') != 'patient':
        return redirect(url_for('login'))
    return render_template('patient_dashboard.html', user_name=session['user_name'])

@app.route('/patient_appointment')
def patient_appointment():
    if not session.get('logged_in') or session.get('user_role') != 'patient':
        return redirect(url_for('login'))
    appointments = get_appointments_for_patient(session['user_id'])
    return render_template('patient_appointment.html', appointments=appointments)

@app.route('/patient_details/<patient_id>')
def patient_details(patient_id):
    if session.get('user_role') != 'doctor':
        return redirect(url_for('login'))
    patient = get_patient_details(patient_id)
    if not patient:
        return "Patient not found", 404
    patient['recent_metrics'] = get_health_metrics_for_patient(patient_id)
    return render_template('patient_details.html', patient=patient)

if __name__ == '__main__':
    app.run(debug=True)
