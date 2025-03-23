from flask import Flask, render_template, request, redirect, url_for,flash, session,jsonify
import os
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash  # Secure Password Handling
import smtplib  
from twilio.rest import Client   # For sending OTP via SMS (Twilio API)
import random,hashlib

# Initialize Flask App
app = Flask(__name__)
app.secret_key = "vote"  # Required for session handling
from datetime import timedelta
app.permanent_session_lifetime = timedelta(minutes=30)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'  # Redirect to admin login if not authenticated

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'online_voting_system'

#twilio configuration
account_sid = "AC6512bef9aab7fd7abfa10b4cd6ea2fd7"
auth_token = "a87bedc32e8e955100175359ea2aaee5"
twilio_number = "+919502332189"  # Example for an Indian number

 #Initialize Twilio Client
client = Client(account_sid, auth_token)
# Initialize MySQL
mysql = MySQL(app)

otp_storage = {}


# -------------- MODELS --------------
class User(UserMixin):
    """Common User Model for Admin and Voter"""
    def __init__(self, user_id, role):
        self.id = user_id
        self.role = role  # 'admin' or 'voter'
@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM admin WHERE id = %s", (user_id,))
    admin = cur.fetchone()
    if admin:
        cur.close()
        return User(user_id, "admin")
    
    cur.execute("SELECT roll_number FROM voter WHERE roll_number = %s", (user_id,))
    voter = cur.fetchone()
    cur.close()
    if voter:
        return User(user_id, "voter")
    return None
# -------------- ROUTES --------------
@app.route('/')
def home():
    return render_template('welcome.html')
@app.route('/candidate/<candidate_id>')
def candidate_details(candidate_id):
    return render_template(f'{candidate_id}.html')
@app.route('/reset')
def reset():
    return render_template('reset.html')
@app.route('/v1')
def v1():
    return render_template('v1.html')
@app.route('/v2')
def v2():
    return render_template('v2.html')
@app.route('/v3')
def v3():
    return render_template('v3.html')
@app.route('/v4')
def v4():
    return render_template('v4.html')

@app.route('/v5')
def v5():
    return render_template('v5.html')




@app.route('/update_data', methods=['POST'])
def update_election_data():
    registered_candidates = request.form['registered_candidates']
    qualified_candidates = request.form['qualified_candidates']
    registered_voters = request.form['registered_voters']
    accredited_voters = request.form['accredited_voters']
    
    # Store or update these values in your database
    cursor = mysql.connection.cursor()
    cursor.execute("""
        UPDATE election_data 
        SET registered_candidates=%s, qualified_candidates=%s, 
            registered_voters=%s, accredited_voters=%s 
        WHERE id=1
    """, (registered_candidates, qualified_candidates, registered_voters, accredited_voters))
    mysql.connection.commit()
    cursor.close()
    
    return redirect(url_for('admin_dashboard'))





# ---------- ADMIN LOGIN ----------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM admin WHERE full_name = %s AND password = %s", (username, password))
        admin = cur.fetchone()
        cur.close()

        if admin:
            # Store session data to track login
            session['admin_logged_in'] = True
            session['admin_username'] = username  

            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard'))  # Redirect to Admin Dashboard
        else:
            flash("Invalid Username or Password!", "danger")
            return redirect(url_for('admin_login'))  # Redirect back to login page on failure

    return render_template('admin_login.html')  # Render login page




@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        flash("Please log in first!", "warning")
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')


# ---------- ADMIN DASHBOARD ----------
    
    

# ---------- VOTER LOGIN ----------


# ------------------ Route: Voter Login Page ------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("login.html", error="Missing credentials, please try again.")

        print(f"DEBUG: username={username}, password={password}")  # Debug print

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT username, password FROM voter WHERE username = %s", (username,))
        
        voter = cursor.fetchone()
        cursor.close()

        print(f"DEBUG: Retrieved voter={voter}")  # Debug print

        if voter and check_password_hash(voter[1], password):  # Validate hashed password
            session['username'] = voter[0]
            return redirect(url_for('voter_dashboard'))
        else:
            flash("Invalid Username or Password!", "danger")
            return render_template('login.html', error="Invalid Username or Password!")  

    return render_template('login.html')





# ------------------ Route: Send OTP ------------------
'''@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    mobile = data['mobile']

    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))
    otp_storage[mobile] = otp  # Store OTP temporarily (use DB in production)

    
    message = client.messages.create(
        body=f"Your OTP for Online Voting System is {otp}",
        from_=9502332189,
        to=mobile
    )
    

    print(f"OTP sent to {mobile}: {otp}")  # Debugging (Remove in production)
    return jsonify({"message": "OTP sent successfully."})'''

# ------------------ Route: Verify OTP ------------------
'''@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    entered_otp = data['otp']
    
    for mobile, stored_otp in otp_storage.items():
        if entered_otp == stored_otp:
            return jsonify({"message": "OTP verified successfully."})

    return jsonify({"message": "Invalid OTP. Please try again."}), 400'''




# ---------- VOTER DASHBOARD ----------

@app.route('/voter_dashboard')
# Make sure login is required
def voter_dashboard():
    return render_template('voter_dashboard.html')


      

# Voter Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print(request.form)  # Debugging: See what data is coming in

        roll_number = request.form.get('roll_number')  # Safe way to fetch
        if not roll_number:
            flash("Roll Number is required!", "danger")
            return redirect(url_for('register'))  # Redirect back if missing

        full_name = request.form.get('full_name')
        mobile_number = request.form.get('mobile_number')
        email = request.form.get('email')
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'))  
        aadhaar_number = request.form.get('aadhaar_number')
        passkey = request.form.get('passkey')

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO voter (roll_number, full_name, mobile_number, email, username, password, aadhaar_number, passkey)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (roll_number, full_name, mobile_number, email, username, password, aadhaar_number, passkey))

        mysql.connection.commit()
        cur.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')



#instruction rute
@app.route('/instruction')
def instruction():
    return render_template('instruction.html')  # Render the instruction page
#results
@app.route('/results')
def results():
    return render_template('results.html')  # Ensure results.html exists
#vote__________
@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if request.method == 'POST':
        # Handle vote submission
        nominee_id = request.form.get('nominee_id')
        voter_id = request.form.get('voter_id')
        
        if not nominee_id or not voter_id:
            return "Invalid input", 400
        
        # Save vote logic (using mysql.connector)
        try:
            conn = mysql.connector.connect(host="localhost", user="root", password="yourpassword", database="online_voting_system")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO votes (voter_id, nominee_id) VALUES (%s, %s)", (voter_id, nominee_id))
            conn.commit()
            cursor.close()
            conn.close()
            return "Vote successfully cast!", 200
        except mysql.connector.Error as err:
            return f"Error: {err}", 500

    return render_template('vote.html')  # Ensure this template exists


# ---------- REGISTER NOMINEE ----------

app.config['UPLOAD_FOLDER'] = 'static/uploads'


@app.route('/nominee', methods=['GET', 'POST'])
def nominee():
    if request.method == 'POST':
        full_name = request.form['full_name']
        mobile = request.form['mobile']
        email = request.form['email']
        aadhaar_number = request.form['aadhaar_number']
        password = request.form['password']
        campaign_message = request.form['campaign_message']

        # Handling Profile Photo Upload
        profile_photo = request.files['profile_photo']
        if profile_photo and profile_photo.filename != '':
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_photo.filename)
            profile_photo.save(photo_path)
            photo_filename = profile_photo.filename
        else:
            photo_filename = None  # If no photo uploaded

        # Insert nominee details into MySQL
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM nominee WHERE mobile_number = %s", (mobile,))
        existing_nominee = cur.fetchone()
    
        if existing_nominee:
           flash("Mobile number already registered. Please use a different number.", "danger")
           return redirect(url_for('nominee'))
             # Redirect back to the nominee form
        cur.execute("INSERT INTO nominee (full_name, mobile_number, email, aadhaar_number, password_hash, campaign_message, profile_photo) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (full_name, mobile, email, aadhaar_number, password, campaign_message, photo_filename))
        
        
        flash("Nominee registered successfully!", "success")  # Flash message
        mysql.connection.commit()
        cur.close()   
        
        

         # Redirect to registration page

    return render_template('nominee.html')  # Render nominee registration page

# ---------- VALIDATE VOTER FOR VOTING ----------

@app.route("/validate_voter", methods=["POST"])
def validate_voter():
    data = request.json
    roll_number = data.get("roll_number")
    cursor=mysql.connection.cursor()
    cursor.execute("SELECT has_voted FROM voter WHERE roll_number = %s", (roll_number,))
    result = cursor.fetchone()

    if result is None:
        return jsonify({"valid": False})
    elif result[0] == 1:
        return jsonify({"valid": False, "message": "You have already voted!"})
    else:
        return jsonify({"valid": True})

@app.route('/cast_vote', methods=['POST'])
def cast_vote():
    data = request.json
    roll_number = data.get("roll_number")

    # Map candidate IDs to party names
    candidate_parties = {
        1: "Future Leaders",
        2: "People's Voice",
        3: "United Youth",
        4: "Rising Stars",
        5: "Bright Future"
    }
    party_name = candidate_parties.get(data.get("candidate_id"))

    if not party_name:
        return jsonify({"success": False, "message": "Invalid candidate selection!"})
    cursor=mysql.connection.cursor()
    # Check if the voter has already voted
    cursor.execute("SELECT has_voted FROM voter WHERE roll_number = %s", (roll_number,))
    result = cursor.fetchone()

    if result is None or result[0]:  # Voter not found or already voted
        return jsonify({"success": False, "message": "You have already voted or invalid Roll Number!"})

    # Store the vote in the database
    cursor.execute("INSERT INTO votes (roll_number, party_name) VALUES (%s, %s)", (roll_number, party_name))
    cursor.execute("UPDATE voter SET has_voted = 1 WHERE roll_number = %s", (roll_number,))
    mysql.connection.commit()

    return jsonify({"success": True, "message": "Vote cast successfully!"})


@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        passkey = request.form.get('passkey')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('reset'))

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT roll_number FROM voter WHERE passkey = %s", (passkey,))
        voter = cursor.fetchone()

        if not voter:
            flash('Invalid Passkey!', 'danger')
            return redirect(url_for('reset'))

        # **Hash the new password before storing it**
        hashed_password = generate_password_hash(new_password)

        # Update password in database
        cursor.execute("UPDATE voter SET password = %s WHERE passkey = %s", (hashed_password, passkey))
        mysql.connection.commit()
        cursor.close()

        flash('Password reset successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset.html')

#results
@app.route('/get_results', methods=['GET'])
def get_results():
    try:
        cur = mysql.connection.cursor()

        # Fetch all parties and their vote counts, ensuring parties with 0 votes are included
        cur.execute("""
            SELECT p.party_name, COALESCE(COUNT(v.id), 0) AS vote_count
            FROM (SELECT DISTINCT party_name FROM nominee) p
            LEFT JOIN votes v ON p.party_name = v.party_name
            GROUP BY p.party_name
            ORDER BY vote_count DESC
        """)

        results = cur.fetchall()
        cur.close()

        # Convert results to JSON format
        results_list = [{"party_name": row[0], "votes": row[1]} for row in results]

        return jsonify({"status": "closed", "results": results_list})

    except Exception as e:
        print("Error:", str(e))
        return jsonify({"status": "error", "message": str(e)})

# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

# -------------- RUN SERVER --------------
if __name__ == "__main__":
    app.run(debug=True)
