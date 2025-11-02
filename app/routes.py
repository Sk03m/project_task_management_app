import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from .models import User, Task
from .extensions import db, bcrypt, login_manager
from datetime import datetime

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx'}
main = Blueprint('main', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
@login_required
def dashboard():
    if current_user.is_admin:
        tasks = Task.query.all()
        users = User.query.all()
    else:
        tasks = Task.query.filter_by(assigned_to=current_user.id).all()
        users = None
    return render_template('dashboard.html', tasks=tasks, users=users, admin=current_user.is_admin)

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or Email already exists')
            return redirect(url_for('main.register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        is_admin = False
        if User.query.count() == 0:
            is_admin = True

        new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('Account Created. Please Login.')
        return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid email or password')
        return redirect(url_for('main.login'))
    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'User exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password, is_admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User added'}), 201

@main.route('/remove_user/<int:user_id>', methods=['DELETE'])
@login_required
def remove_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot delete self'}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User removed'}), 200

@main.route('/add_task', methods=['POST'])
@login_required
def add_task():
    data = request.json
    title = data.get('title')
    description = data.get('description')
    deadline_str = data.get('deadline')
    assigned_to = data.get('assigned_to')

    if not title or not assigned_to:
        return jsonify({'error': 'Title and assigned_to are required'}), 400
    deadline = None
    if deadline_str:
        deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
    user = User.query.get(assigned_to)
    if not user:
        return jsonify({'error': 'Assigned user not found'}), 404
    new_task = Task(title=title, description=description, deadline=deadline, assigned_to=assigned_to)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task added'}), 201

@main.route('/delete_task/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted'}), 200

@main.route('/complete_task/<int:task_id>', methods=['PUT'])
@login_required
def complete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx', 'ppt', 'pptx'}

    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    filename = secure_filename(file.filename)
    upload_folder = os.path.join(current_app.root_path, 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)

    task.file_name = filename
    task.status = 'Completed'
    db.session.commit()

    return jsonify({'message': 'Task marked as completed and file uploaded'}), 200

@main.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    upload_folder = os.path.join(current_app.root_path, 'uploads')
    return send_from_directory(upload_folder, filename)
