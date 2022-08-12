from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User,Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    return redirect('/register')


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.username.data
        pwd = form.password.data
        email = form.email.data
        fname = form.first_name.data
        lname = form.last_name.data
        new_user = User.register(name, pwd, email,fname,lname)

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken.  Please pick another')
            return render_template('register.html', form=form)
        session['username'] = new_user.username
        #user = User.query.get(name)
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f'/users/{name}')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f'/users/{username}')
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)

@app.route("/secret")
def secret():
    """Example hidden page for logged-in users only."""

    if "username" not in session:
        flash("You must be logged in to view!")
        return redirect("/")

        # alternatively, can return HTTP Unauthorized status:
        #
        # from werkzeug.exceptions import Unauthorized
        # raise Unauthorized()

    else:
        return render_template("secret.html")

@app.route('/users/<username>')
def show_user(username):
    """show user"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    user = User.query.get_or_404(username)
    if user.username == session['username']:
        user = User.query.get(username)
        feedbacks = Feedback.query.all()
        return render_template('/users.html', user= user, feedbacks=feedbacks)
    return redirect('/')


@app.route('/feedbacks/<int:id>', methods=["GET","POST"])
def edit_feedback(id):
    """edit feedback"""
    
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    form = FeedbackForm()    
    feedback = Feedback.query.get_or_404(id)
    form.title.data = feedback.title
    form.content.data = feedback.content
    if feedback.username == session['username']:
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            db.session.add(feedback)
            db.session.commit()
            return redirect(f'/users/{feedback.username}')	

        return render_template('/edit_feedback.html', form = form , feedback=feedback)
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{feedback.username}')	

@app.route('/feedbacks', methods=['GET', 'POST'])
def add_feedback():
    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_feedback = Feedback(title=title,content=content, username=session['username'])
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback Created!', 'success')
        return redirect(f'/users/{new_feedback.username}')
    
    return render_template('feedback.html', form=form)


@app.route('/feedbacksdelete/<int:id>', methods=["POST"])
def delete_feedback(id):
    """Delete feedback"""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    feedback = Feedback.query.get_or_404(id)
    if feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted!", "info")
        username =session['username']
        return redirect(f'/users/{username}')
    flash("You don't have permission to do that!", "danger")
    return redirect(f'/users/{username}')

@app.route('/users/<username>/delete')
def delete_user(username):
     """Delete user"""
     if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
     deluser = User.query.get_or_404(username)
     feedbacks=Feedback.query.filter_by(username = deluser.username)
     if deluser.username == session['username']:
        for i in feedbacks:
            db.session.delete(i)
        db.session.delete(deluser)
        db.session.commit()
        flash("User deleted!", "info")
        return redirect('/')
     flash("You don't have permission to do that!", "danger")
     return redirect(f'/users/{username}')

@app.route('/logout')
def logout_user():
    session.pop('username')
    flash("Goodbye!", "info")
    return redirect('/')        