from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps

from sqlalchemy import Column, Integer, String, Text, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, declarative_base, Mapped, mapped_column

import forms
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
Base = declarative_base()
db = SQLAlchemy(app, model_class=Base)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    password = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)

    # Define a one-to-many relationship with BlogPost
    posts = relationship('BlogPost', back_populates='author', lazy=True)
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(Base):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250),
                     nullable=False)  # https://www.jetsetter.com//uploads/sites/7/2018/04/up76yDnt-1380x1035.jpeg

    # Define a foreign key to link to the User table
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    comments = relationship("Comment", back_populates="parent_post")


class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    text = Column(Text, nullable=False)
    # ***************Child Relationship*************#
    author_id = Column(Integer, ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')
    # ***************Child Relationship*************#
    post_id = Column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


def admin_only(func):
    @wraps(func)
    def allow_user(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return allow_user


@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return db.session.get(User, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        check_email = db.session.query(User).filter_by(email=form.email.data).first()
        if not check_email:
            hash_pass = generate_password_hash(form.password.data, 'pbkdf2', 16)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=hash_pass,
                date=date.today().strftime('%d/%m/%Y')
            )
            with app.app_context():
                db.session.execute(db.select(User))
                db.session.add(new_user)
                db.session.commit()
                return redirect('/')
        else:
            flash('User already exists, please login')
            return redirect('login')
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    user_credentials = LoginForm()
    if user_credentials.validate_on_submit():
        user_email = user_credentials.email.data
        user_pass = user_credentials.password.data
        check_email = db.session.query(User).filter_by(email=user_email).first()
        if check_email:
            check_pass = check_password_hash(check_email.password, user_pass)
            if check_pass:
                login_user(check_email)
                user_name = check_email.name
                return redirect('/')  # url_for('/', name=user_name)
            else:
                flash('incorrect password, please try again')
                # return redirect(url_for('login'))
        else:
            flash('The email does not exist, please try again')
            # return redirect(url_for('login'))  # url_for was necessary to display the flash here. X

    return render_template("login.html", form=user_credentials)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comments = CommentForm()
    # Fetch comments related to the post
    all_comments = db.session.query(Comment).filter_by(post_id=post_id).all()
    if comments.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Please login to comment')
            return redirect(url_for('login'))
        else:
            new_comment = Comment(
                text=comments.comment.data,
                author_id=current_user.id,
                post_id=requested_post.id
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html",
                           post=requested_post, form=comments, user_comments=all_comments
                           )


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
