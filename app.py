from flask import Flask, render_template, request, redirect, url_for, session, flash
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import re
import random
import string

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Configure SendGrid
SENDGRID_API_KEY = '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'
SENDER_EMAIL = 'sharmin@peakup.in'

users = []

def generate_secret_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def send_verification_email(email, secret_key):
    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=email,
        subject='Roar.ai Email Verification',
        html_content=f'Your verification code is: {secret_key}'
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(str(e))

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#\$%\^&\*]", password):
        return False
    return True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = next((user for user in users if user['email'] == email and user['password'] == password), None)
        if user:
            session['user'] = email
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    plan = request.args.get('plan', 'free_trial')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not is_strong_password(password):
            flash('Password must be at least 8 characters long, contain an uppercase letter, a number, and a special character.')
            return redirect(url_for('register', plan=plan))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register', plan=plan))

        secret_key = generate_secret_key()
        session['temp_user'] = {'email': email, 'password': password, 'plan': plan, 'secret_key': secret_key}
        
        send_verification_email(email, secret_key)
        
        return redirect(url_for('verify_email'))
    return render_template('register.html', plan=plan)

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        entered_key = request.form['secret_key']
        if session['temp_user']['secret_key'] == entered_key:
            users.append({
                'email': session['temp_user']['email'],
                'password': session['temp_user']['password'],
                'plan': session['temp_user']['plan']
            })
            session.pop('temp_user', None)
            return redirect(url_for('login'))
        else:
            flash('Verification Failed')
    return render_template('verify_email.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = next((user for user in users if user['email'] == email), None)
        if user:
            secret_key = generate_secret_key()
            session['reset_user'] = {'email': email, 'secret_key': secret_key}
            send_verification_email(email, secret_key)
            return redirect(url_for('reset_password_verify'))
        else:
            flash('Email not found')
    return render_template('forgot_password.html')

@app.route('/reset_password_verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        entered_key = request.form['secret_key']
        if session['reset_user']['secret_key'] == entered_key:
            return redirect(url_for('reset_password'))
        else:
            flash('Verification Failed')
    return render_template('reset_password_verify.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password']
        email = session['reset_user']['email']
        user = next((user for user in users if user['email'] == email), None)
        if user:
            user['password'] = new_password
            session.pop('reset_user', None)
            return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome to your dashboard, {session['user']}!"
    else:
        return redirect(url_for('login'))

@app.route('/plans')
def plans():
    return render_template('plans.html')

if __name__ == '__main__':
    app.run(debug=True)
