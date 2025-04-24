from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session, send_file
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Email, Length
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Date, JSON, Boolean, DateTime, func
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import stripe
import os
import smtplib
import json
import datetime
import os
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from forms import AuthForms, FeedbackForm
from datetime import datetime, date
from werkzeug.utils import secure_filename
from flask_bootstrap import Bootstrap5
import subprocess
import platform
import uuid


APP_NAME = 'Ticklis'
stripe.api_key = os.environ.get('STRIPE_API')


app = Flask(__name__)
# Initialize Bootstrap after creating the app
bootstrap = Bootstrap5(app)
ckeditor = CKEditor(app)
app.config['SECRET_KEY'] = "os.environ.get('SECRET_KEY')"

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", 'sqlite:///users.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

#user DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    premium_level: Mapped[int] = mapped_column(Integer)
    date_of_signup: Mapped[Date] = mapped_column(Date)
    end_date_premium: Mapped[Date] = mapped_column(Date)
    email_opt_in: Mapped[bool] = mapped_column(Boolean, default=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_token: Mapped[str] = mapped_column(String(100), nullable=True)
    stripe_customer_id: Mapped[str] = mapped_column(String(100), nullable=True)
    stripe_active_subscription: Mapped[bool] = mapped_column(Boolean, default=False)
    pdf_uploads: Mapped[int] = mapped_column(Integer, default=0)
    monthly_questions: Mapped[int] = mapped_column(Integer, default=0)
    misc1: Mapped[str] = mapped_column(String(100), nullable=True)
    misc2: Mapped[str] = mapped_column(String(100), nullable=True)
    misc3: Mapped[str] = mapped_column(String(100), nullable=True)
    miscnum1: Mapped[int] = mapped_column(Integer, nullable=True)
    miscnum2: Mapped[int] = mapped_column(Integer, nullable=True)
    miscnum3: Mapped[int] = mapped_column(Integer, nullable=True)

# Add new StripeLog model after other models
class StripeLog(db.Model):
    __tablename__ = "stripe_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime, default=datetime.utcnow)
    event_type: Mapped[str] = mapped_column(String(100))
    user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    stripe_customer_id: Mapped[str] = mapped_column(String(100), nullable=True)
    request_data: Mapped[str] = mapped_column(String(5000))  # Store request JSON
    response_data: Mapped[str] = mapped_column(String(5000), nullable=True)  # Store response JSON
    status: Mapped[str] = mapped_column(String(50))  # Success/Error
    error_message: Mapped[str] = mapped_column(String(500), nullable=True)

class FeedbackUpvote(db.Model):
    __tablename__ = "feedback_upvotes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feedback_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("feedback.id"))
    cookie_id: Mapped[str] = mapped_column(String(64))  # Store a unique cookie ID instead of user_id

# Update Feedback class to include relationship
class Feedback(db.Model):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(50))
    feedback: Mapped[str] = mapped_column(String())
    upvote_count: Mapped[int] = mapped_column(Integer)

class blog_posts(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    date: Mapped[Date] = mapped_column(Date)
    content: Mapped[str] = mapped_column(String())
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    slug: Mapped[str] = mapped_column(String(200), unique=True)

class Todo(db.Model):
    __tablename__ = "todos"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    text: Mapped[str] = mapped_column(String(500))
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    completed_at: Mapped[DateTime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime, default=datetime.utcnow)
    # Add relationship to User
    user = relationship("User", backref="todos")

class Suggestion(db.Model):
    __tablename__ = "suggestions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)



with app.app_context():
    db.create_all()


@app.route('/', methods=["GET", "POST"])
def home_page():
    return render_template('todo.html')

@app.route('/price-page', methods=["GET", "POST"])
def price_page():
    return render_template("price_page.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    form = AuthForms.RegisterForm()
    if form.validate_on_submit():
        try:
            # Check if user email is already present in the database.
            result = db.session.execute(db.select(User).where(User.email == form.email.data.lower()))
            user = result.scalar()
            if user:
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('login'))
            
            hash_and_salted_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=form.email.data.lower(),
                name=form.name.data,
                password=hash_and_salted_password,
                date_of_signup=date.today(),
                end_date_premium=date.today(),
                premium_level=0,
                verified=True,
                email_opt_in=True,
                pdf_uploads=0,
                monthly_questions=0
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Log in the user immediately after registration
            login_user(new_user)
            flash("Registration successful! Welcome to Ticklis!")
            return redirect(url_for("home_page"))
                
        except Exception as e:
            print(f"Registration error: {str(e)}")
            flash("An error occurred during registration. Please try again.")
            return redirect(url_for("register"))
            
    return render_template("register.html", form=form, current_user=current_user)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = AuthForms.LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data.lower()))
        user = result.scalar()
        
        if not user:
            flash("That email does not exist, please try again.")
            print(f"User not found: {form.email.data.lower()}")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            print(f"Password incorrect: {form.email.data.lower()}")
            return redirect(url_for('login'))
        elif not user.verified:
            flash('Please verify your email before logging in.')
            print(f"Email not verified: {form.email.data.lower()}")
            return redirect(url_for('login'))
        else:
            print(f"Login successful: {form.email.data.lower()}")
            login_user(user)
            flash('Login successful! Welcome to Ticklis!')
            return redirect(url_for('home_page'))

    return render_template("login.html", form=form, current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home_page'))

'''Commenting out for now

#for test of Stripe
YOUR_DOMAIN = 'http://127.0.0.1:5002'
#for live of Stripe
DOMAIN2 = 'https://ticklis.com'

@app.route('/create-checkout-session', methods=['POST', 'GET'])
def create_checkout_session():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    plan = request.args.get('plan')
    try:
        # Log the initial request
        log_entry = StripeLog(
            event_type='create_checkout_session',
            user_id=current_user.id,
            stripe_customer_id=current_user.stripe_customer_id,
            request_data=json.dumps({'plan': plan}),
            status='pending'
        )
        db.session.add(log_entry)
        db.session.commit()

        if plan == 'mbasic':
            price_id = 'price_1QvLalAT83osEdRmOOAwRJFm'  # Your Basic Plan Price ID
            product_name = 'Monthly Basic Membership'
        elif plan == 'mpro':
            price_id = 'price_1QvLakAT83osEdRmmE7pJ5yN'  # Your Pro Plan Price ID
            product_name = 'Monthly Pro Membership'
        elif plan == 'ybasic':
            price_id = 'price_1QvLaiAT83osEdRmpI8QpDSb'  # Your Basic Plan Price ID
            product_name = 'Yearly Basic Membership'
        elif plan == 'ypro':
            price_id = 'price_1QvLafAT83osEdRm8jHUL8qo'  # Your Pro Plan Price ID
            product_name = 'Yearly Pro Membership'
        elif plan == 'daily':
            price_id = 'price_1QvM7VAT83osEdRmaQgpvPaq'  # Your Basic Plan Price ID
            product_name = 'Daily Membership'
        else:
            return "Invalid plan selected", 400

        # Create or get Stripe Customer
        if current_user.stripe_customer_id:  # Assuming misc1 stores Stripe customer ID
            customer = stripe.Customer.retrieve(current_user.stripe_customer_id)
        else:
            customer = stripe.Customer.create(
                email=current_user.email,
                metadata={
                    'user_id': current_user.id
                }
            )
            # Store Stripe customer ID in user record
            current_user.stripe_customer_id = customer.id
            db.session.commit()

        checkout_session = stripe.checkout.Session.create(
            customer=customer.id,  # Use the customer ID
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            allow_promotion_codes=True,
            success_url=DOMAIN2 + f'/success?plan={plan}&session_id={{CHECKOUT_SESSION_ID}}',
            cancel_url=DOMAIN2 + '/cancel',
            metadata={
                'user_id': current_user.id
            }
        )

        # Update log with success response
        log_entry.status = 'success'
        log_entry.response_data = json.dumps({
            'checkout_session_id': checkout_session.id,
            'url': checkout_session.url
        })
        db.session.commit()

        return redirect(checkout_session.url, code=303)

    except Exception as e:
        # Log the error
        if log_entry:
            log_entry.status = 'error'
            log_entry.error_message = str(e)
            db.session.commit()
        print(f"Error creating checkout session: {str(e)}")
        return str(e)

@app.route('/webhook', methods=['POST'])
def webhook():
    print("Webhook endpoint hit!")
    
    # Truncate request data to 4900 chars to leave room for formatting
    truncated_data = request.data.decode('utf-8')[:4900]
    
    # Create initial log entry before any processing
    initial_log = StripeLog(
        event_type='webhook_received',
        request_data=truncated_data,
        status='received'
    )
    db.session.add(initial_log)
    db.session.commit()
    
    try:
        payload = request.data
        sig_header = request.headers.get('STRIPE_SIGNATURE')
        
        if not sig_header:
            print("No Stripe signature found in headers!")
            initial_log.status = 'error'
            initial_log.error_message = 'No Stripe signature in headers'
            db.session.commit()
            return 'No signature', 400
            
        print(f"Received payload: {payload.decode('utf-8')[:200]}...")  # Print first 200 chars
        print(f"Signature header: {sig_header}")
        
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.environ.get('STRIPE_WEBHOOK_SECRET')
        )
        
        print(f"Event type: {event['type']}")
        
        # Add handling for subscription cancellation/deletion
        if event['type'] in ['customer.subscription.deleted', 'customer.subscription.canceled']:
            subscription = event['data']['object']
            customer_id = subscription.customer
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                # Reset user's subscription status
                user.premium_level = 0
                user.stripe_active_subscription = False
                # Set end_date to current period end (subscription remains active until end of period)
                user.end_date_premium = datetime.fromtimestamp(subscription.current_period_end)
                db.session.commit()
                initial_log.status = 'success'
                initial_log.response_data = json.dumps({
                    'subscription_id': subscription.id,
                    'customer_id': customer_id,
                    'user_id': user.id if user else None,
                    'action': 'subscription_cancelled'
                })[:4900]  # Truncate response data

        # Handle different event types...
        if event['type'] == 'customer.subscription.created':
            subscription = event['data']['object']
            customer_id = subscription.customer
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                user.premium_level = 1 if subscription.plan.id == 'price_1QvLalAT83osEdRmOOAwRJFm' or subscription.plan.id == 'price_1QvLaiAT83osEdRmpI8QpDSb' else 2
                user.end_date_premium = datetime.fromtimestamp(subscription.current_period_end)
                user.stripe_active_subscription = True
                db.session.commit()
                initial_log.status = 'success'
                initial_log.response_data = json.dumps({
                    'subscription_id': subscription.id,
                    'customer_id': customer_id,
                    'user_id': user.id if user else None,
                    'action': 'subscription_created'
                })[:4900]  # Truncate response data

        elif event['type'] == 'customer.subscription.updated':
            subscription = event['data']['object']
            customer_id = subscription.customer
            
            # Enhanced logging
            print(f"Processing subscription update for customer {customer_id}")
            print(f"Subscription status: {subscription.status}")
            print(f"Subscription plan: {subscription.plan.id}")
            
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            
            if not user:
                print(f"No user found for customer_id: {customer_id}")
                initial_log.status = 'error'
                initial_log.error_message = f'No user found for customer_id: {customer_id}'
                db.session.commit()
                return jsonify({'error': 'User not found'}), 400
            
            print(f"Found user: {user.id} ({user.email})")
            
            try:
                # Update user subscription status based on subscription status
                if subscription.status == 'active':
                    user.premium_level = 1 if subscription.plan.id == 'price_1QvLalAT83osEdRmOOAwRJFm' or subscription.plan.id == 'price_1QvLaiAT83osEdRmpI8QpDSb' else 2
                    user.end_date_premium = datetime.fromtimestamp(subscription.current_period_end)
                    user.stripe_active_subscription = True
                    print(f"Updated user {user.id} to premium_level: {user.premium_level}")
                elif subscription.status in ['canceled', 'unpaid', 'past_due']:
                    user.stripe_active_subscription = False
                    print(f"Marked subscription as inactive for user {user.id}")
                
                # Update log entry
                initial_log.status = 'success'
                initial_log.response_data = json.dumps({
                    'subscription_id': subscription.id,
                    'customer_id': customer_id,
                    'user_id': user.id,
                    'action': 'subscription_updated',
                    'subscription_status': subscription.status,
                    'premium_level': user.premium_level,
                    'end_date': user.end_date_premium.isoformat() if user.end_date_premium else None
                })[:4900]  # Truncate response data
                
                db.session.commit()
                print(f"Successfully processed subscription update for user {user.id}")
                
            except Exception as e:
                db.session.rollback()
                error_msg = f"Error processing subscription update: {str(e)}"
                print(error_msg)
                initial_log.status = 'error'
                initial_log.error_message = error_msg[:500]  # Truncate error message to fit column
                db.session.commit()
                return jsonify({'error': error_msg[:500]}), 500

        elif event['type'] == 'invoice.payment_succeeded':
            invoice = event['data']['object']
            # Only handle subscription-related invoices
            if invoice.subscription:
                subscription = stripe.Subscription.retrieve(invoice.subscription)
                customer_id = invoice.customer
                user = User.query.filter_by(stripe_customer_id=customer_id).first()
                if user and subscription.status == 'active':
                    # Update the end date with the new period end
                    user.end_date_premium = datetime.fromtimestamp(subscription.current_period_end)
                    user.stripe_active_subscription = True
                    db.session.commit()
                    initial_log.status = 'success'
                    initial_log.response_data = json.dumps({
                        'invoice_id': invoice.id,
                        'subscription_id': subscription.id if invoice.subscription else None,
                        'customer_id': customer_id,
                        'user_id': user.id if user else None,
                        'action': 'payment_succeeded'
                    })[:4900]  # Truncate response data

        db.session.commit()
        return 'Success', 200

    except Exception as e:
        initial_log.status = 'error'
        initial_log.error_message = str(e)[:500]  # Truncate error message to fit column
        db.session.commit()
        return str(e), 400

@app.route('/cancel', methods=['POST', 'GET'])
def cancel_session():
    return redirect(url_for('price_page'))

@app.route('/success', methods=['GET'])
@login_required
def success_session():
    session_id = request.args.get('session_id')
    if not session_id:
        return redirect(url_for('price_page'))
        
    try:
        # Retrieve the session
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        # Store customer ID if not already stored
        if not current_user.stripe_customer_id:
            current_user.stripe_customer_id = checkout_session.customer
            db.session.commit()
        
        # Update user's subscription status
        subscription = stripe.Subscription.retrieve(checkout_session.subscription)
        # Check the price ID instead of plan name
        current_user.premium_level = 1 if subscription.plan.id == 'price_1QuLzDAT83osEdRmnyTHcbDp' or subscription.plan.id == 'price_1QvLaiAT83osEdRmpI8QpDSb' else 2
        current_user.end_date_premium = datetime.fromtimestamp(subscription.current_period_end)
        current_user.stripe_active_subscription = True  # Set subscription to active
        db.session.commit()
        
        flash('Thank you for your subscription!', 'success')
        return redirect(url_for('home_page'))
        
    except Exception as e:
        print(f"Error processing subscription: {str(e)}")
        flash('There was an error processing your subscription. Please contact support.', 'error')
        return redirect(url_for('price_page'))

@app.route('/manage-membership', methods=['POST', 'GET'])
@login_required
def manage_membership():
    if not current_user.stripe_customer_id:
        flash('No active subscription found.', 'warning')
        return redirect(url_for('price_page'))
        
    try:
        # Create Stripe billing portal session
        session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=DOMAIN2 + '/profile',
        )
        
        # Redirect to Stripe billing portal
        return redirect(session.url)
        
    except stripe.error.StripeError as e:
        print(f"Stripe error: {str(e)}")
        flash('Error accessing subscription information. Please try again later.', 'error')
        return redirect(url_for('profile'))
    except Exception as e:
        print(f"Error: {str(e)}")
        flash('An unexpected error occurred. Please try again later.', 'error')
        return redirect(url_for('profile'))
'''
@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route('/privacy-policy', methods=['POST', 'GET'])
def privacy_policy():
    return render_template("privacy_policy.html")

@app.route('/terms-and-conditions', methods=['POST', 'GET'])
def terms_and_conditions():
    return render_template("terms_and_conditions.html")

@app.route('/change-password', methods=["GET", "POST"])
@login_required
def change_password():
    form = AuthForms.ChangePasswordForm()
    if form.validate_on_submit():
        # Check if the email matches the logged-in user's email
        if form.email.data.lower() != current_user.email:
            flash("You can only change your own password.", "error")
            return redirect(url_for('change_password'))
            
        # Verify current password
        if not check_password_hash(current_user.password, form.password.data):
            flash('Current password incorrect, please try again.', "error")
            return redirect(url_for('change_password'))
            
        # Update password
        current_user.password = generate_password_hash(
            form.new_password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        db.session.commit()
        flash('Password changed successfully', "success")
        return redirect(url_for('change_password'))

    return render_template("change_password.html", form=form, current_user=current_user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = AuthForms.ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            user.verification_token = reset_token
            db.session.commit()
            
            try:
                sender_email = os.environ.get('EMAIL_ADDRESS')
                sender_password = os.environ.get('EMAIL_PASSWORD')
                
                msg = MIMEMultipart()
                msg['From'] = sender_email
                msg['To'] = user.email
                msg['Subject'] = f"Reset Your {APP_NAME} Password"
                
                html = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
                            <h1 style="color: #333;">Password Reset Request</h1>
                        </div>
                        <div style="padding: 20px;">
                            <p>We received a request to reset your password. Click the button below to create a new password:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{DOMAIN2}/reset-password/{reset_token}" 
                                   style="background-color: #007bff; color: white; padding: 12px 25px; 
                                          text-decoration: none; border-radius: 5px;">
                                    Reset Password
                                </a>
                            </div>
                            <p style="color: #666; font-size: 0.9em;">
                                If you didn't request this reset, you can safely ignore this email.<br>
                                The reset link will expire in 1 hour.
                            </p>
                        </div>
                    </body>
                </html>
                """
                
                msg.attach(MIMEText(html, 'html'))
                
                with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
                    connection.starttls()
                    connection.login(user=sender_email, password=sender_password)
                    connection.send_message(msg)
                
                flash('Password reset instructions have been sent to your email.', 'success')
            except Exception as e:
                print(f"Error sending reset email: {str(e)}")
                flash('Error sending reset email. Please try again or contact support.', 'error')
                
        else:
            # Still show success message to prevent email enumeration
            flash('If an account exists with that email, password reset instructions have been sent.', 'success')
            
        return redirect(url_for('login'))
        
    return render_template("forgot_password.html", form=form)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # First verify the token
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        flash('Invalid or expired reset link. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    form = AuthForms.ResetPasswordForm()
    
    if form.validate_on_submit():
        # Update password
        user.password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        user.verification_token = None  # Clear the token after use
        db.session.commit()
        
        flash('Your password has been reset successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
        
    # Pass form and token to template
    return render_template('reset_password.html', form=form, token=token)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    form = FeedbackForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Create new feedback
        new_feedback = Feedback(
            title=form.title.data,
            feedback=form.feedback.data,
            upvote_count=0,
        )
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback submitted successfully!', 'feedback-success')
        return redirect(url_for('feedback'))
    
    # Get feedback data
    feedback_list = Feedback.query.all()
    
    # Get upvoted feedback IDs from cookie
    upvoted_feedback_ids = []
    cookie_id = request.cookies.get('feedback_cookie_id')
    if cookie_id:
        upvoted_feedback = FeedbackUpvote.query.filter_by(cookie_id=cookie_id).all()
        upvoted_feedback_ids = [f.feedback_id for f in upvoted_feedback]
    
    return render_template("feedback.html", form=form, feedback_list=feedback_list, upvoted_feedback_ids=upvoted_feedback_ids)

@app.route('/delete-feedback/<feedback_id>', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback deleted successfully!', 'feedback-success')
    return jsonify({'success': True})

@app.route('/upvote/<int:feedback_id>', methods=['POST'])
def upvote_feedback(feedback_id):
    # Get or create cookie ID
    cookie_id = request.cookies.get('feedback_cookie_id')
    if not cookie_id:
        cookie_id = str(uuid.uuid4())
    
    feedback = Feedback.query.get_or_404(feedback_id)
    existing_upvote = FeedbackUpvote.query.filter_by(
        cookie_id=cookie_id,
        feedback_id=feedback_id
    ).first()

    if existing_upvote:
        db.session.delete(existing_upvote)
        feedback.upvote_count -= 1
    else:
        new_upvote = FeedbackUpvote(cookie_id=cookie_id, feedback_id=feedback_id)
        db.session.add(new_upvote)
        feedback.upvote_count += 1

    db.session.commit()
    
    response = jsonify({'upvote_count': feedback.upvote_count})
    if not request.cookies.get('feedback_cookie_id'):
        response.set_cookie('feedback_cookie_id', cookie_id, max_age=60*60*24*365*2)  # 2 years
    
    return response

def send_verification_email(email, token):
    try:
        sender_email = os.environ.get('EMAIL_ADDRESS')
        sender_password = os.environ.get('EMAIL_PASSWORD')
        
        if not sender_email or not sender_password:
            print("Email credentials not found in environment variables")
            flash("Error sending verification email. Please contact support.")
            return False
        
        # Create MIME message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = f"Verify Your {APP_NAME} Account"
        
        # Create HTML body
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background-color: #f8f9fa; padding: 20px; text-align: center;">
                    <h1 style="color: #333;">Welcome to {APP_NAME}!</h1>
                </div>
                <div style="padding: 20px;">
                    <p>Thank you for registering! Please verify your email address to complete your account setup.</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{DOMAIN2}/verify/{token}" 
                           style="background-color: #007bff; color: white; padding: 12px 25px; 
                                  text-decoration: none; border-radius: 5px;">
                            Verify Email
                        </a>
                    </div>
                    <p style="color: #666; font-size: 0.9em;">
                        If the button doesn't work, copy and paste this link into your browser:<br>
                        {DOMAIN2}/verify/{token}
                    </p>
                </div>
            </body>
        </html>
        """
        
        msg.attach(MIMEText(html, 'html'))
        
        # Send email
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()
            try:
                connection.login(user=sender_email, password=sender_password)
                connection.send_message(msg)
                return True
            except smtplib.SMTPAuthenticationError:
                print("Failed to authenticate with Gmail")
                flash("Error sending verification email. Please contact support.")
                return False
                
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        flash("Error sending verification email. Please contact support.")
        return False

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.verified = True
        user.verification_token = None  # Clear the token after use
        db.session.commit()
        flash("Your email has been verified! You can now log in.")
    else:
        flash("Invalid verification token.")
    return redirect(url_for('login'))

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    email = request.form.get('email')
    if not email:
        flash("Please enter your email address first.")
        return redirect(url_for('login'))
        
    user = User.query.filter_by(email=email.lower()).first()
    if not user:
        flash("No account found with that email address.")
        return redirect(url_for('login'))
        
    if user.verified:
        flash("This email is already verified.")
        return redirect(url_for('login'))
        
    # Generate new verification token
    new_token = secrets.token_urlsafe(32)
    user.verification_token = new_token
    db.session.commit()
    
    if send_verification_email(email, new_token):
        flash("Verification email has been resent. Please check your inbox and spam folder. Email will come from mwdynamics@gmail.com")
    else:
        flash("Error sending verification email. Please try again or contact support.")
    
    return redirect(url_for('login'))
'''Commenting out for now
@app.route('/blog')
def blog():
    # Get all blog posts ordered by date descending
    posts = db.session.execute(db.select(blog_posts).order_by(blog_posts.date.desc())).scalars()
    return render_template('blog.html', posts=posts)

@app.route('/blog/<string:post_slug>')
def show_post(post_slug):
    # Get specific blog post by slug
    post = blog_posts.query.filter_by(slug=post_slug).first_or_404()
    
    related_posts = blog_posts.query.filter(
        blog_posts.id != post.id,
        (blog_posts.title.ilike(f"%{post.title}%") | 
         blog_posts.content.ilike(f"%{post.content}%"))
    ).limit(5).all()
    
    random_posts = blog_posts.query.order_by(func.random()).limit(4).all()
    return render_template('blog_post.html', post=post, related_posts=related_posts, random_posts=random_posts)

@app.route('/new-post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = BlogPostForm()
    if form.validate_on_submit():
        # Create URL-friendly slug from title
        slug = "-".join(form.title.data.lower().split())
        
        new_post = blog_posts(
            title=form.title.data,
            content=form.content.data,
            date=date.today(),
            author_id=current_user.id,
            slug=slug
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('blog'))
        
    return render_template('create_blog_post.html', form=form)

@app.route('/cron/reset-monthly-questions', methods=['POST'])
def cron_reset_monthly_questions():
    # Verify the request is from Render using a secret token
    auth_token = request.headers.get('Authorization')
    expected_token = os.environ.get('CRON_SECRET_TOKEN')
    
    if not auth_token or auth_token != f"Bearer {expected_token}":
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Reset monthly_questions to 0 for all users
        User.query.update({User.monthly_questions: 0})
        db.session.commit()
        
        # Log the successful reset
        print(f"Successfully reset monthly questions at {datetime.now()}")
        return jsonify({
            'success': True,
            'message': 'Monthly questions reset successfully',
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error resetting monthly questions: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

'''
@app.route('/launch-app', methods=['POST'])
def launch_app():
    try:
        data = request.get_json()
        app_name = data.get('app_name')
        
        # Map of app names to their web URLs
        app_urls = {
            'lucidchart': 'https://www.lucidchart.com',
            'draw.io': 'https://app.diagrams.net',
            'miro': 'https://miro.com',
            'google_slides': 'https://slides.google.com',
            'prezi': 'https://prezi.com',
            'canva': 'https://www.canva.com',
            'google_sheets': 'https://sheets.google.com',
            'airtable': 'https://airtable.com',
            'zoho_sheet': 'https://sheet.zoho.com',
            'notion': 'https://www.notion.so',
            'evernote': 'https://www.evernote.com',
            'onenote': 'https://www.onenote.com',
            'todoist': 'https://todoist.com',
            'asana': 'https://asana.com',
            'trello': 'https://trello.com',
            'figma': 'https://www.figma.com',
            'photopea': 'https://www.photopea.com',
            'clipchamp': 'https://clipchamp.com',
            'kapwing': 'https://www.kapwing.com',
            'wevideo': 'https://www.wevideo.com',
            'google_meet': 'https://meet.google.com',
            'zoom': 'https://zoom.us',
            'microsoft_teams': 'https://teams.microsoft.com',
            'gmail': 'https://mail.google.com',
            'outlook': 'https://outlook.live.com',
            'yahoo_mail': 'https://mail.yahoo.com',
            'slack': 'https://slack.com',
            'discord': 'https://discord.com',
            'google_docs': 'https://docs.google.com',
            'microsoft_word': 'https://www.office.com/launch/word',
            'zoho_writer': 'https://writer.zoho.com',
            'monday': 'https://monday.com',
            'jira': 'https://www.atlassian.com/software/jira',
            'clickup': 'https://clickup.com',
            'google_drive': 'https://drive.google.com',
            'dropbox': 'https://www.dropbox.com',
            'onedrive': 'https://onedrive.live.com',
            'adobe_xd': 'https://xd.adobe.com',
            'github_codespaces': 'https://github.com/features/codespaces',
            'replit': 'https://replit.com',
            'codesandbox': 'https://codesandbox.io',
            'google_data_studio': 'https://datastudio.google.com',
            'tableau': 'https://public.tableau.com',
            'power_bi': 'https://app.powerbi.com',
            'supabase': 'https://supabase.com',
            'firebase': 'https://firebase.google.com',
            'mongodb_atlas': 'https://www.mongodb.com/cloud/atlas',
            'excel': 'https://www.office.com/launch/excel',
            'mysql': 'https://www.mysql.com',
            'pgadmin': 'https://www.pgadmin.org',
            'mongodb': 'https://www.mongodb.com',
            'vscode': 'https://code.visualstudio.com',
            'intellij': 'https://www.jetbrains.com/idea',
            'sublime': 'https://www.sublimetext.com',
            'visio': 'https://www.microsoft.com/en-us/microsoft-365/visio/flowchart-software',
            'powerpoint': 'https://www.office.com/launch/powerpoint',
            'numbers': 'https://www.apple.com/numbers/',
            'microsoft_todo': 'https://todo.microsoft.com',
            'photoshop': 'https://www.adobe.com/products/photoshop.html',
            'illustrator': 'https://www.adobe.com/products/illustrator.html',
            'premiere': 'https://www.adobe.com/products/premiere.html',
            'camtasia': 'https://www.techsmith.com/video-editor.html',
            'davinci': 'https://www.blackmagicdesign.com/products/davinciresolve',
            'acrobat': 'https://www.adobe.com/acrobat.html',
            'microsoft_project': 'https://www.microsoft.com/en-us/microsoft-365/project/project-management-software',
            'sketch': 'https://www.sketch.com',
            'dbeaver': 'https://dbeaver.io'
        }
        
        # Convert app_name to lowercase and replace spaces with underscores
        app_key = app_name.lower().replace(' ', '_')
        
        if app_key in app_urls:
            return jsonify({
                'success': True,
                'web_url': app_urls[app_key]
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Application not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Error launching app: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while launching the application'
        }), 500

@app.route('/api/todos', methods=['GET'])
@login_required
def get_todos():
    todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.created_at.asc()).all()
    return jsonify([{
        'id': todo.id,
        'text': todo.text,
        'completed': todo.completed,
        'completed_at': todo.completed_at.isoformat() if todo.completed_at else None,
        'created_at': todo.created_at.isoformat()
    } for todo in todos])

@app.route('/api/todos', methods=['POST'])
@login_required
def add_todo():
    data = request.get_json()
    todo = Todo(
        text=data['text'],
        user_id=current_user.id
    )
    db.session.add(todo)
    db.session.commit()
    return jsonify({
        'id': todo.id,
        'text': todo.text,
        'completed': todo.completed,
        'completed_at': todo.completed_at.isoformat() if todo.completed_at else None,
        'created_at': todo.created_at.isoformat()
    })

@app.route('/api/todos/<int:todo_id>', methods=['PUT'])
@login_required
def update_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
    data = request.get_json()
    
    if 'text' in data:
        todo.text = data['text']
    if 'completed' in data:
        todo.completed = data['completed']
        if data['completed'] and not todo.completed_at:
            todo.completed_at = datetime.utcnow()
        elif not data['completed']:
            todo.completed_at = None
    
    db.session.commit()
    return jsonify({
        'id': todo.id,
        'text': todo.text,
        'completed': todo.completed,
        'completed_at': todo.completed_at.isoformat() if todo.completed_at else None,
        'created_at': todo.created_at.isoformat()
    })

@app.route('/api/todos/<int:todo_id>', methods=['DELETE'])
@login_required
def delete_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
    db.session.delete(todo)
    db.session.commit()
    return '', 204

@app.route('/api/todos/<int:todo_id>', methods=['GET'])
@login_required
def get_todo(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
    return jsonify({
        'id': todo.id,
        'text': todo.text,
        'completed': todo.completed,
        'completed_at': todo.completed_at.isoformat() if todo.completed_at else None,
        'created_at': todo.created_at.isoformat()
    })

@app.route('/api/suggestions', methods=['POST'])
def submit_suggestion():
    data = request.get_json()
    name = data.get('name')
    category = data.get('category')
    
    # Validate required fields
    if not name or not category:
        return jsonify({
            'error': 'Missing required fields: name and category are required'
        }), 400
    
    # Create a new suggestion
    suggestion = Suggestion(
        name=name,
        category=category
    )
    db.session.add(suggestion)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Suggestion submitted successfully'
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=5002)




