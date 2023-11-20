import os
import time
from flask import (
    Flask, 
    render_template, 
    url_for,
    redirect,
    flash,
    send_from_directory,
    request,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin,
    LoginManager,
    login_user, 
    logout_user,
    login_required,
    current_user,
)
from flask_wtf import FlaskForm
from wtforms import (
    StringField, 
    SelectField,
    PasswordField, 
    SubmitField,
    FileField,
    IntegerField,
)
from flask_migrate import Migrate
from wtforms.validators import (
    ValidationError,
    InputRequired, 
    Length, 
    EqualTo,
    Email,
    NumberRange,
)
from flask_wtf.file import (
    FileAllowed, 
    FileRequired,
)
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from functools import wraps


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key_example'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'product_pictures'

db = SQLAlchemy()
migrate = Migrate(app, db)
bcrypt = Bcrypt()

login_manager = LoginManager(app)
login_manager.login_view = "login"


def init_app(app):
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)

init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    """Define User table and its parametres."""

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')


class JewelryType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    material = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255), nullable=True)  
    jewelry_type_id = db.Column(db.Integer, db.ForeignKey('jewelry_type.id'), nullable=False)
    jewelry_type = db.relationship('JewelryType', backref=db.backref('products', lazy=True))

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product', backref=db.backref('carts', lazy=True))
    quantity = db.Column(db.Integer, default=1)

    def __init__(self, user_id, product_id, quantity=1):
        self.user_id = user_id
        self.product_id = product_id
        self.quantity = quantity

    def update_quantity(self, quantity):
        self.quantity += quantity
        db.session.commit()

    def saveToDB(self):
        db.session.add(self)
        db.session.commit()

    def deleteFromDB(self):
        db.session.delete(self)
        db.session.commit()


class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product', backref=db.backref('wishlists', lazy=True))

    def __init__(self, user_id, product_id):
        self.user_id = user_id
        self.product_id = product_id

    def saveToDB(self):
        db.session.add(self)
        db.session.commit()

    def deleteFromDB(self):
        db.session.delete(self)
        db.session.commit()


def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == 'admin':
            return func(*args, **kwargs)
        else:
            return "Permission denied", 403  
    return decorated_view


class RegistrationForm(FlaskForm):
    """Registration form with validation."""

    first_name = StringField(
        'First Name', 
        validators=[InputRequired(), Length(max=20)],
        render_kw={"placeholder": "First name"}
    )
    last_name = StringField(
        'Last Name', 
        validators=[InputRequired(), Length(max=20)],
        render_kw={"placeholder": "Last name"}
    )
    email = StringField(
        'Email',
        validators=[InputRequired(), Email(), Length(max=120)],  
        render_kw={"placeholder": "Email"}  
    )
    role = SelectField(
        'Role', 
        choices=[('user', 'User'), ('admin', 'Admin')], default='user'
    )
    password = PasswordField(
        'Password', 
        validators=[InputRequired(), Length(min=6), 
                    EqualTo('confirm_password', message='Passwords must match')],
        render_kw={"placeholder": "Password"}
    )
    confirm_password = PasswordField(
        'Confirm Password', 
        validators=[InputRequired()],
        render_kw={"placeholder": "Confirm Password"}
    )
    submit = SubmitField(
        'Register'
    )

    def validate_email(self, email):  
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'That email is already registered. Please choose a different one.'
            )


class LoginForm(FlaskForm):
    """Login form."""

    email = StringField(
        'Username', 
        validators=[InputRequired()],
        render_kw={"placeholder": "Email"}
    )
    password = PasswordField(
        'Password', 
        validators=[InputRequired()],
        render_kw={"placeholder": "Confirm Password"}
    )
    submit = SubmitField('Login')


class ProductForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), Length(max=100)])
    material = StringField('Material', validators=[InputRequired(), Length(max=50)])
    price = IntegerField('Price', validators=[InputRequired(), NumberRange(min=0)])
    image = FileField('Image', validators=[])
    jewelry_type_id = SelectField('Jewelry Type', coerce=int, validators=[InputRequired()])

    def __init__(self, *args, **kwargs):
        super(ProductForm, self).__init__(*args, **kwargs)
        self.jewelry_type_id.choices = [(jewelry_type.id, jewelry_type.name) for jewelry_type in JewelryType.query.all()]


@app.route('/', endpoint='home')
def home():
    products = Product.query.all()
    return render_template('home.html', products=products)


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    products = Product.query.all()
    return render_template('admin.html', products=products)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Serching if user with such email exists
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user is None:
                # If user doesn't exist, creating a new one with current data
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                new_user = User(
                    first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    email=form.email.data,
                    password=hashed_password,
                    role=form.role.data
                )
                db.session.add(new_user)
                db.session.commit()
                # Starting new user's session
                login_user(new_user)
                flash('Your account has been created!', 'success')
                return redirect(url_for('home')) or redirect('/')
        except:
            flash('An error occurred while registering your account.', 'danger')
        else:
            flash('That email is already in use. Please choose a different one.', 'danger')
    return render_template('registration.html', form=form)


@app.route('/product_pictures/<filename>')
def product_pictures(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/admin/dashboard/create_product', methods=['GET', 'POST'])
@admin_required
def create_product():
    form = ProductForm()

    if form.validate_on_submit():
        image = form.image.data

        # Regenerating pictures' names so they won't be replaced or rewrited 
        filename = secure_filename(f"{str(int(time.time()))}_{image.filename}")

        # Сохраняем изображение в папку 'product_pictures' вашего приложения
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        product = Product(
            name=form.name.data,
            material=form.material.data,
            price=form.price.data,
            image=filename,  # Path to current picture
            jewelry_type_id=form.jewelry_type_id.data
        )

        db.session.add(product)
        db.session.commit()

        flash('Product created successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('create_product.html', form=form)


@app.route('/admin/dashboard/edit_product/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)

    if form.validate_on_submit():
        if form.image.data:
            image = form.image.data
            filename = secure_filename(f"{str(int(time.time()))}_{image.filename}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            product.image = filename

        product.name = form.name.data
        product.material = form.material.data
        product.price = form.price.data
        product.jewelry_type_id = form.jewelry_type_id.data

        db.session.commit()

        flash('Product updated successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('edit_product.html', form=form, product=product)


@app.route('/admin/dashboard/delete_product/<int:product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    product.delete()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart_item = Cart.query.filter_by(user_id=current_user.id, product_id=product.id).first()

    if cart_item:
        cart_item.update_quantity(1)
    else:
        cart_item = Cart(user_id=current_user.id, product_id=product.id)
        cart_item.saveToDB()

    flash('Product added to cart successfully!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))


@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = Cart.query.get_or_404(cart_item_id)

    if cart_item.user_id == current_user.id:
        cart_item.deleteFromDB()
        flash('Product removed from cart successfully!', 'success')
    else:
        flash('You do not have permission to remove this product from the cart.', 'danger')

    return redirect(url_for('cart'))


@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
@login_required
def add_to_wishlist(product_id):
    product = Product.query.get_or_404(product_id)
    wishlist_item = Wishlist.query.filter_by(user_id=current_user.id, product_id=product.id).first()

    if wishlist_item:
        flash('Product is already in your wishlist.', 'warning')
    else:
        wishlist_item = Wishlist(user_id=current_user.id, product_id=product.id)
        wishlist_item.saveToDB()
        flash('Product added to wishlist successfully!', 'success')

    return redirect(url_for('product_detail', product_id=product_id))


@app.route('/remove_from_wishlist/<int:wishlist_item_id>', methods=['POST'])
@login_required
def remove_from_wishlist(wishlist_item_id):
    wishlist_item = Wishlist.query.get_or_404(wishlist_item_id)

    if wishlist_item.user_id == current_user.id:
        wishlist_item.deleteFromDB()
        flash('Product removed from wishlist successfully!', 'success')
    else:
        flash('You do not have permission to remove this product from the wishlist.', 'danger')

    return redirect(url_for('wishlist'))


@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()

    return render_template('cart.html', cart_items=cart_items)


@app.route('/wishlist')
@login_required
def wishlist():
    wishlist_items = Wishlist.query.filter_by(user_id=current_user.id).all()

    return render_template('wishlist.html', wishlist_items=wishlist_items)


if __name__ == "__main__":
    app.run(debug=True, port=5000)