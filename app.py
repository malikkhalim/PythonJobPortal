from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash
from models import User, Job, Course
import shelve

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class JobForm(FlaskForm):
    title = StringField('Job Title', validators=[DataRequired(), Length(min=1, max=100)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=1, max=500)])
    requirements = TextAreaField('Requirements', validators=[DataRequired(), Length(min=1, max=500)])
    submit = SubmitField('Post')

class CourseForm(FlaskForm):
    title = StringField('Course Title', validators=[DataRequired(), Length(min=1, max=100)])
    submit = SubmitField('Add Course')

class PasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

@login_manager.user_loader
def load_user(user_id):
    return User.get_user(user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.add_user(form.username.data, form.password.data):
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_user_by_username(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    jobs = Job.get_jobs()
    password_form = PasswordForm()
    if password_form.validate_on_submit():
        if current_user.check_password(password_form.current_password.data):
            db = shelve.open('data.db', writeback=True)
            db['users'][current_user.id]['password'] = generate_password_hash(password_form.new_password.data)
            db.close()
            flash('Password updated successfully', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Current password is incorrect', 'danger')
    courses = []
    db = shelve.open('data.db')
    if 'applied_courses' in db and current_user.id in db['applied_courses']:
        courses = db['applied_courses'][current_user.id]
    db.close()
    return render_template('profile.html', jobs=jobs, password_form=password_form, courses=courses)

@app.route('/job_listings')
def job_listings():
    jobs = Job.get_jobs()
    return render_template('job_listing.html', jobs=jobs)

@app.route('/courses')
def courses():
    courses = Course.get_courses()
    return render_template('courses.html', courses=courses)

@app.route('/apply_job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply_job(job_id):
    jobs = Job.get_jobs()
    job = jobs[job_id]
    if request.method == 'POST':
        cover_letter = request.form.get('cover_letter')
        if not cover_letter:
            flash('Cover letter is required', 'danger')
        else:
            flash('Application submitted successfully', 'success')
    return render_template('apply_job.html', job=job)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('index'))
    
    form = CourseForm()
    job_form = JobForm()
    if form.validate_on_submit():
        Course.add_course(form.title.data)
        flash('Course added successfully', 'success')
        return redirect(url_for('admin'))
    if job_form.validate_on_submit():
        Job.add_job(job_form.title.data, job_form.description.data, job_form.requirements.data)
        flash('Job posted successfully', 'success')
        return redirect(url_for('admin'))
    
    jobs = Job.get_jobs()
    db = shelve.open('data.db')
    transactions = db.get('transactions', [])
    db.close()
    return render_template('admin.html', jobs=jobs, transactions=transactions, form=form, job_form=job_form)

@app.route('/post_job', methods=['GET', 'POST'])
@login_required
def post_job():
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('index'))
    
    form = JobForm()
    if form.validate_on_submit():
        Job.add_job(form.title.data, form.description.data, form.requirements.data)
        flash('Job posted successfully', 'success')
        return redirect(url_for('job_listings'))
    return render_template('job_post.html', form=form)

@app.route('/enroll_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
def enroll_course(course_id):
    courses = Course.get_courses()
    course = courses[course_id]
    db = shelve.open('data.db', writeback=True)
    if 'applied_courses' not in db:
        db['applied_courses'] = {}
    if current_user.id not in db['applied_courses']:
        db['applied_courses'][current_user.id] = []
    db['applied_courses'][current_user.id].append(course)
    db.close()
    flash('Enrolled in course successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/add_course', methods=['GET', 'POST'])
@login_required
def add_course():
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('index'))
    
    form = CourseForm()
    if form.validate_on_submit():
        Course.add_course(form.title.data)
        flash('Course added successfully', 'success')
        return redirect(url_for('courses'))
    return render_template('add_course.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
