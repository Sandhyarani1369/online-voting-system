from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, bcrypt, Voter, Nominee, Votes, Admin
from config import Config
from sqlalchemy.sql import func
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Voter.query.get(int(user_id)) or Admin.query.get(int(user_id))

# Home Page
@app.route('/')
def welcome():
    return render_template('welcome.html')

# Instructions Page
@app.route('/instruction')
def instruction():
    return render_template('instruction.html')

# Voter Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Voter.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('voter_dashboard'))
        else:
            flash('Invalid login credentials', 'danger')

    return render_template('login.html')

# Admin Login Page
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin = admin.query.filter_by(username=username).first()

        if admin and check_password_hash(admin.password, password):
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('admin_login.html')

# Admin Dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Voter Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        mobile = request.form['mobile']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        new_voter = Voter(name=name, email=email, mobile=mobile, password=password)
        db.session.add(new_voter)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Voting Page
@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    if request.method == 'POST':
        nominee_id = request.form['nominee_id']

        # Ensure voter has not already voted
        existing_vote = Votes.query.filter_by(voter_id=current_user.id).first()
        if existing_vote:
            flash('You have already voted!', 'danger')
            return redirect(url_for('voter_dashboard'))

        new_vote = Votes(voter_id=current_user.id, nominee_id=nominee_id)
        db.session.add(new_vote)
        db.session.commit()
        flash('Your vote has been cast successfully!', 'success')
        return redirect(url_for('voter_dashboard'))

    nominees = Nominee.query.all()
    return render_template('vote.html', nominees=nominees)

# Dynamic Results Page
@app.route('/results')
def results():
    vote_counts = (
        db.session.query(
            Nominee.id, Nominee.name, Nominee.party, Nominee.symbol,
            func.count(Votes.id).label("vote_count")
        )
        .outerjoin(Votes, Nominee.id == Votes.nominee_id)
        .group_by(Nominee.id)
        .all()
    )

    if not vote_counts:
        return render_template("results.html", message="Results will be declared after elections.")

    winner = max(vote_counts, key=lambda x: x.vote_count) if vote_counts else None
    return render_template("results.html", vote_counts=vote_counts, winner=winner)

# Dynamic Nominee List Page
@app.route('/candidate')
def candidate():
    nominees = Nominee.query.all()
    if not nominees:
        return render_template("candidate.html", message="No nominees registered yet.")
    return render_template("candidate.html", nominees=nominees)

# Register Nominee
@app.route('/nominee', methods=['GET', 'POST'])
@login_required
def nominee():
    if request.method == 'POST':
        name = request.form['name']
        party = request.form['party']
        symbol = request.form['symbol']

        new_nominee = Nominee(name=name, party=party, symbol=symbol)
        db.session.add(new_nominee)
        db.session.commit()
        flash('Nominee registered successfully!', 'success')
        return redirect(url_for('candidate'))

    return render_template('nominee.html')

# Voter Dashboard
@app.route('/voter_dashboard')
@login_required
def voter_dashboard():
    return render_template("voter_dashboard.html", user=current_user)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
