from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView


auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        if current_user.is_authenticated:
            flash("You are already logged in!", category="error")
            return redirect(url_for("views.home"))
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password.', category='error')
        else:
            flash('Email does not exist.', category=error)

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == "GET":
        if current_user.is_authenticated:
            flash("You are already logged in!", category="error")
            return redirect(url_for("views.home"))
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters!', category='error')
        elif len(firstName) < 2:
            flash('First name must be greater than 1 characters!', category='error')
        elif password1 != password2:
            flash('Passwords need to match!', category='error')
        elif len(password1) < 7:
            flash('Password must be greater than 6 characters!', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
    return render_template("sign_up.html", user=current_user)

@auth.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        firstName = request.form.get('firstName')
        
        current_user.firstName = firstName
        db.session.commit()

        flash('Account details edited successfully!', category='success')
        return redirect(url_for('views.home'))
    return render_template("edit.html", user=current_user)

class AdminView(ModelView):
    def is_accessible(self):
        if current_user.is_authenticated:
            admin_status = current_user.is_admin
            return admin_status
        else:
            return False
    def inaccessible_callback(self, name, **kwargs):
        flash("You need to be an admin to see that page!", category="error")
        return redirect(url_for('views.home'))

@auth.route('/admin')
@login_required
def admin():
    pass

