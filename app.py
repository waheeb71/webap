from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from models import db, User, Lecture, News, Announcement

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'

# تأكد من وجود المجلد وإنشائه إذا لم يكن موجودًا
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    announcements = Announcement.query.all()
    user_count = User.query.count()
    visitor_count = sum(user.visits for user in User.query.all())
    return render_template('base.html', announcements=announcements, user_count=user_count, visitor_count=visitor_count)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    user_count = User.query.count()
    visitor_count = sum(user.visits for user in User.query.all())
    return render_template('register.html', user_count=user_count, visitor_count=visitor_count)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            user.visits += 1
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Check your username and password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        title = request.form.get('title')
        level = request.form.get('level')
        term = request.form.get('term')
        file = request.files['file']
        if file:
            filename = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_lecture = Lecture(title=title, filename=filename, user_id=current_user.id, level=level, term=term)
            db.session.add(new_lecture)
            db.session.commit()
            flash('Lecture uploaded successfully!', 'success')
            return redirect(url_for('lectures'))
    return render_template('upload.html')

@app.route('/lectures', methods=['GET', 'POST'])
@login_required
def lectures():
    if request.method == 'POST':
        level = request.form.get('level')
        term = request.form.get('term')
        lectures = Lecture.query.filter_by(user_id=current_user.id, level=level, term=term).all()
        return render_template('lectures.html', lectures=lectures, level=level, term=term)
    return render_template('lectures_select.html')

@app.route('/cybersecurity', methods=['GET', 'POST'])
@login_required
def cybersecurity():
    if request.method == 'POST':
        if 'delete' in request.form:
            news_id = request.form.get('delete')
            news_item = News.query.get(news_id)
            if news_item:
                db.session.delete(news_item)
                db.session.commit()
                flash('News deleted successfully!', 'success')
        else:
            password = request.form.get('password')
            if password == 'waheeb2004126':
                title = request.form.get('title')
                content = request.form.get('content')
                file = request.files.get('file')
                filename = None
                if file:
                    filename = file.filename
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_news = News(title=title, content=content, image_filename=filename, user_id=current_user.id)
                db.session.add(new_news)
                db.session.commit()
                flash('News uploaded successfully!', 'success')
            else:
                flash('Incorrect password!', 'danger')
    news_list = News.query.all()
    return render_template('cybersecurity.html', news_list=news_list)

@app.route('/news', methods=['GET'])
def news():
    news_list = News.query.all()
    return render_template('news.html', news_list=news_list)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username == 'waheeb2004126' and check_password_hash(current_user.password, 'waheeb2004126'):
        if request.method == 'POST':
            if 'delete' in request.form:
                announcement_id = request.form.get('delete')
                announcement = Announcement.query.get(announcement_id)
                if announcement:
                    db.session.delete(announcement)
                    db.session.commit()
                    flash('Announcement deleted successfully!', 'success')
            else:
                title = request.form.get('title')
                content = request.form.get('content')
                file = request.files.get('file')
                filename = None
                if file:
                    filename = file.filename
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_announcement = Announcement(title=title, content=content, image_filename=filename, user_id=current_user.id)
                db.session.add(new_announcement)
                db.session.commit()
                flash('Announcement uploaded successfully!', 'success')
                return redirect(url_for('admin'))
        announcements = Announcement.query.all()
        return render_template('admin.html', announcements=announcements)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))

@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    if current_user.username == 'waheeb2004126' and check_password_hash(current_user.password, 'waheeb2004126'):
        if request.method == 'POST':
            user_id = request.form.get('delete')
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
                return redirect(url_for('users'))
        users = User.query.all()
        return render_template('users.html', users=users)
    else:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
