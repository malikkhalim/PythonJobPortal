import shelve
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, password, is_admin=False):
        self.id = id
        self.username = username
        self.password = password  # Store the hashed password
        self.is_admin = is_admin

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @staticmethod
    def get_user(user_id):
        db = shelve.open('data.db')
        if 'users' not in db:
            db['users'] = {}
        user_data = db['users'].get(user_id)
        db.close()
        if user_data:
            return User(user_id, user_data['username'], user_data['password'], user_data['is_admin'])
        return None

    @staticmethod
    def get_user_by_username(username):
        db = shelve.open('data.db')
        if 'users' not in db:
            db['users'] = {}
        user_data = next((user for user in db['users'].values() if user['username'] == username), None)
        if user_data:
            user_id = list(db['users'].keys())[list(db['users'].values()).index(user_data)]
            return User(user_id, user_data['username'], user_data['password'], user_data['is_admin'])
        db.close()
        return None

    @staticmethod
    def add_user(username, password, is_admin=False):
        db = shelve.open('data.db', writeback=True)
        if 'users' not in db:
            db['users'] = {}
        if username in [user['username'] for user in db['users'].values()]:
            db.close()
            return False
        user_id = str(len(db['users']) + 1)
        db['users'][user_id] = {'username': username, 'password': generate_password_hash(password), 'is_admin': is_admin}
        db.close()
        return True

    def get_id(self):
        return self.id

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

class Job:
    @staticmethod
    def add_job(title, description, requirements):
        db = shelve.open('data.db', writeback=True)
        if 'jobs' not in db:
            db['jobs'] = []
        job = {'title': title, 'description': description, 'requirements': requirements}
        db['jobs'].append(job)
        db.close()

    @staticmethod
    def get_jobs():
        db = shelve.open('data.db')
        if 'jobs' not in db:
            db['jobs'] = []
        jobs = db['jobs']
        db.close()
        return jobs

class Course:
    @staticmethod
    def add_course(title):
        db = shelve.open('data.db', writeback=True)
        if 'courses' not in db:
            db['courses'] = []
        course = {'title': title}
        db['courses'].append(course)
        db.close()

    @staticmethod
    def get_courses():
        db = shelve.open('data.db')
        if 'courses' not in db:
            db['courses'] = []
        courses = db['courses']
        db.close()
        return courses
