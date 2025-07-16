from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import boto3
import os
import uuid
from datetime import datetime
import json
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.config import Config
from boto3.dynamodb.conditions import Key

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here' # Replace with a strong secret key

# Initialize DynamoDB client
# Ensure DynamoDB Local is running on this endpoint
dynamodb = boto3.resource('dynamodb',
                          region_name='ap-south-1',
                          endpoint_url='http://localhost:8000',
                          aws_access_key_id='dummy',
                          aws_secret_access_key='dummy',
                          config=Config(signature_version='v4'))

# DynamoDB table names (ensure these tables exist in your local DynamoDB)
users_table = dynamodb.Table('MedTrackUsers')
appointments_table = dynamodb.Table('MedTrackAppointments')
diagnoses_table = dynamodb.Table('MedTrackDiagnoses')
metrics_table = dynamodb.Table('MedTrackHealthMetrics')

# --- Helper Functions ---
def get_user_by_email(email):
    """Fetches a user from DynamoDB by email (primary key)."""
    try:
        response = users_table.get_item(Key={'email': email})
        return response.get('Item')
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

def get_patient_details_by_id(user_id):
    """Fetches details for a specific patient from DynamoDB by user_id using GSI."""
    try:
        # Assuming 'user_id-index' is a GSI on MedTrackUsers table with user_id as HASH key
        response = users_table.query(
            IndexName='user_id-index',
            KeyConditionExpression=Key('user_id').eq(user_id)
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        print(f"Error getting patient details by user_id: {e}")
        return None

def create_user(name, email, password_hash, role):
    """Creates a new user in DynamoDB."""
    try:
        users_table.put_item(
            Item={
                'user_id': str(uuid.uuid4()),
                'name': name,
                'email': email,
                'password_hash': password_hash,
                'role': role,
                'created_at': datetime.now().isoformat()
            }
        )
        return True
    except Exception as e:
        print(f"Error creating user: {e}")
        return False

def get_appointments_for_patient(patient_id):
    """Fetches appointments for a given patient from DynamoDB."""
    try:
        response = appointments_table.query(
            IndexName='patient_id-index', # You'll need to create this GSI in DynamoDB
            KeyConditionExpression=Key('patient_id').eq(patient_id)
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error fetching patient appointments: {e}")
        return []

def get_appointments_for_doctor(doctor_id):
    """Fetches appointments for a given doctor from DynamoDB."""
    try:
        response = appointments_table.query(
            IndexName='doctor_id-index', # You'll need to create this GSI in DynamoDB
            KeyConditionExpression=Key('doctor_id').eq(doctor_id)
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error fetching doctor appointments: {e}")
        return []

def get_all_patients():
    """Fetches all users with 'patient' role from DynamoDB using GSI."""
    try:
        response = users_table.query(
            IndexName='role-index', # You'll need to create this GSI in DynamoDB
            KeyConditionExpression=Key('role').eq('patient')
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error fetching all patients: {e}")
        return []

def get_all_doctors():
    """Fetches all users with 'doctor' role from DynamoDB using GSI."""
    try:
        response = users_table.query(
            IndexName='role-index', # You'll need to create this GSI in DynamoDB
            KeyConditionExpression=Key('role').eq('doctor')
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error fetching all doctors: {e}")
        return []

def get_diagnoses_for_patient(patient_id):
    """Fetches diagnoses for a given patient from DynamoDB."""
    try:
        response = diagnoses_table.query(
            IndexName='patient_id-index', # Assuming a patient_id-index on diagnoses table
            KeyConditionExpression=Key('patient_id').eq(patient_id)
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error fetching patient diagnoses: {e}")
        return []

def get_health_metrics_for_patient(patient_id):
    """Fetches health metrics for a given patient from DynamoDB (latest 3)."""
    try:
        response = metrics_table.query(
            IndexName='patient_id-index', # Assuming a patient_id-index on metrics table
            KeyConditionExpression=Key('patient_id').eq(patient_id),
            Limit=3,
            ScanIndexForward=False # Get most recent first
        )
        return response.get('Items', [])
    except Exception as e:
        print(f"Error fetching patient health metrics: {e}")
        return []

# --- Routes ---
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
        email = request.form['email']
        password = request.form['password']
        selected_role = request.form.get('role')

        user = get_user_by_email(email)

        if user and check_password_hash(user['password_hash'], password):
            if user['role'] != selected_role:
                flash(f'Login failed. Your account is registered as a {user["role"]}, not a {selected_role}.', 'error')
                return f'Login failed. Your account is registered as a {user["role"]}, not a {selected_role}.', 401

            session['logged_in'] = True
            session['user_id'] = user['user_id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            flash('Logged in successfully!', 'success')
            if user['role'] == 'patient':
                return redirect(url_for('patient_dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            return "Invalid email or password.", 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        terms_agreed = 'terms' in request.form
        selected_role = request.form.get('role', 'patient')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return "Passwords do not match.", 400
        if not terms_agreed:
            flash('You must agree to the Terms of Service and Privacy Policy.', 'error')
            return "You must agree to the Terms of Service and Privacy Policy.", 400

        if get_user_by_email(email):
            flash('Email already registered. Please login or use a different email.', 'error')
            return "Email already registered. Please login or use a different email.", 409

        hashed_password = generate_password_hash(password)
        if create_user(name, email, hashed_password, role=selected_role):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login', registered='true'))
        else:
            flash('Registration failed. Please try again.', 'error')
            return "Registration failed. Please try again.", 500

    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/patient_dashboard')
def patient_dashboard():
    if not session.get('logged_in') or session.get('user_role') != 'patient':
        flash('Please log in as a patient to access this page.', 'error')
        return redirect(url_for('login'))

    patient_id = session['user_id']

    upcoming_appointments = get_appointments_for_patient(patient_id)
    recent_diagnoses = get_diagnoses_for_patient(patient_id)
    health_metrics = get_health_metrics_for_patient(patient_id)

    health_overview = {}
    for metric in health_metrics:
        if metric.get('metric_type') == 'weight':
            health_overview['last_weight'] = f"{metric.get('value')} {metric.get('unit', 'kg')} ({datetime.fromisoformat(metric.get('recorded_at')).strftime('%Y-%m-%d')})"
        elif metric.get('metric_type') == 'blood_pressure':
            health_overview['last_bp'] = f"{metric.get('value')} {metric.get('unit', 'mmHg')} ({datetime.fromisoformat(metric.get('recorded_at')).strftime('%Y-%m-%d')})"
        elif metric.get('metric_type') == 'heart_rate':
            health_overview['last_hr'] = f"{metric.get('value')} {metric.get('unit', 'bpm')} ({datetime.fromisoformat(metric.get('recorded_at')).strftime('%Y-%m-%d')})"

    return render_template(
        'patient_dashboard.html',
        user_name=session.get('user_name'),
        upcoming_appointments=upcoming_appointments,
        recent_diagnoses=recent_diagnoses,
        health_overview=health_overview
    )


@app.route('/doctor_dashboard')
def doctor_dashboard():
    if not session.get('logged_in') or session.get('user_role') != 'doctor':
        flash('Please log in as a doctor to access this page.', 'error')
        return redirect(url_for('login'))
    
    doctor_id = session['user_id']
    
    # Fetch upcoming appointments and enrich with patient names
    upcoming_appointments_raw = get_appointments_for_doctor(doctor_id)
    upcoming_appointments = []
    for appt in upcoming_appointments_raw:
        patient = get_patient_details_by_id(appt['patient_id'])
        if patient:
            appt['patient_name'] = patient.get('name', 'Unknown Patient')
            upcoming_appointments.append(appt)

    # Fetch pending diagnoses and enrich with patient names
    all_diagnoses = []
    try:
        # In a real app, you'd query diagnoses directly assigned to the doctor.
        # This scan is inefficient for large tables. Ensure 'patient_id-index' on diagnoses table.
        response = diagnoses_table.scan() 
        all_diagnoses = response.get('Items', [])
    except Exception as e:
        print(f"Error scanning diagnoses: {e}")

    pending_diagnoses = []
    for diag in all_diagnoses:
        if diag.get('status') == 'Pending Review':
            patient = get_patient_details_by_id(diag['patient_id'])
            if patient:
                diag['patient_name'] = patient.get('name', 'Unknown Patient')
                pending_diagnoses.append(diag)

    patient_list = get_all_patients() # Get all patients registered in the system

    return render_template('doctor_dashboard.html', 
                           user_name=session.get('user_name'),
                           upcoming_appointments=upcoming_appointments,
                           pending_diagnoses=pending_diagnoses,
                           patient_list=patient_list)

@app.route('/doctor_patients_list')
def doctor_patients_list():
    if not session.get('logged_in') or session.get('user_role') != 'doctor':
        flash('Please log in as a doctor to access this page.', 'error')
        return redirect(url_for('login'))
    
    patients = get_all_patients()
    return render_template('doctor_patients_list.html', patient_list=patients)

@app.route('/appointment', methods=['GET', 'POST'])
def appointment():
    if request.method == 'POST':
        try:
            data = request.get_json()

            doctor_id = data.get('doctor')  # corresponds to name="doctor" in HTML
            date = data.get('appointment_date')
            time = data.get('appointment_time')
            reason = data.get('reason', 'General consultation')
            patient_id = session.get('user_id')  # from login session

            if not all([doctor_id, date, time, reason, patient_id]):
                return jsonify({"success": False, "message": "Missing required fields"}), 400

            appointment_id = str(uuid.uuid4())
            created_at = datetime.now().isoformat()

            # Store the appointment in DynamoDB
            appointments_table.put_item(Item={
                'appointment_id': appointment_id,
                'doctor_id': doctor_id,
                'patient_id': patient_id,
                'date': date,
                'time': time,
                'reason': reason,
                'status': 'pending',
                'created_at': created_at
            })

            return jsonify({"success": True, "message": "Appointment booked successfully"}), 200

        except Exception as e:
            print(f"Error booking appointment: {e}")
            return jsonify({"success": False, "message": "Server error occurred."}), 500

    # GET request – show the form
    if not session.get('logged_in') or session.get('user_role') != 'patient':
        flash('Please log in as a patient to book an appointment.', 'error')
        return redirect(url_for('login'))

    doctors = get_all_doctors()
    return render_template('appointment.html', doctors=doctors)




@app.route('/patient_appointment')
def patient_appointment():
    if not session.get('logged_in') or session.get('user_role') != 'patient':
        flash('Please log in as a patient to view your appointments.', 'error')
        return redirect(url_for('login'))
    
    patient_id = session['user_id']
    my_appointments = get_appointments_for_patient(patient_id)
    
    return render_template('patient_appointment.html', appointments=my_appointments)

@app.route('/patient_details/<patient_id>')
def patient_details(patient_id):
    if not session.get('logged_in') or session.get('user_role') not in ['doctor', 'patient']:
        flash('Please log in to view patient details.', 'error')
        return redirect(url_for('login'))

    if not patient_id:
        flash('Invalid patient ID.', 'error')
        return redirect(url_for('login'))

    try:
        response = users_table.get_item(Key={'user_id': patient_id})
        patient_data = response.get('Item')

        if not patient_data:
            flash('Patient record not found.', 'error')
            return redirect(url_for('login'))

        return render_template('patient_details.html', patient=patient_data)

    except Exception as e:
        print("Error fetching patient details:", e)
        flash('An error occurred while fetching patient details.', 'error')
        return redirect(url_for('login'))


    
    # Ensure a patient can only view their own details, doctors can view any patient
    if session.get('user_role') == 'patient' and session.get('user_id') != patient_id:
        flash('Unauthorized access to patient details.', 'error')
        return redirect(url_for('patient_dashboard')) # Redirect patient to their own dashboard

    patient = get_patient_details_by_id(patient_id)
    if not patient:
        flash('Patient not found.', 'error')
        return redirect(url_for('doctor_dashboard')) # Or an error page
    
    # Parse JSON strings back into Python objects
    if 'medical_history_json' in patient:
        try:
            patient['medical_history'] = json.loads(patient['medical_history_json'])
        except json.JSONDecodeError:
            patient['medical_history'] = []
    else:
        patient['medical_history'] = []

    if 'medications_json' in patient:
        try:
            patient['medications'] = json.loads(patient['medications_json'])
        except json.JSONDecodeError:
            patient['medications'] = []
    else:
        patient['medications'] = []
    
    if 'allergies_list' in patient:
        patient['allergies'] = patient['allergies_list'] # Assuming this is already a list
    else:
        patient['allergies'] = []

    patient['recent_metrics'] = get_health_metrics_for_patient(patient_id)

    return render_template('patient_details.html', patient=patient, session_user_role=session.get('user_role'))

if __name__ == '__main__':
    app.run(debug=True)
