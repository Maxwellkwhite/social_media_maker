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
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from forms import AuthForms, FeedbackForm, TwoByTwoForm
from datetime import datetime, date
from werkzeug.utils import secure_filename
from flask_bootstrap import Bootstrap5
import subprocess
import platform
import uuid
import time
from instagrapi import Client
from instagrapi.exceptions import LoginRequired, ClientError


APP_NAME = 'Ticklis'
stripe.api_key = os.environ.get('STRIPE_API')

# Instagram API Configuration
INSTAGRAM_USERNAME = 'PortableDocs'
INSTAGRAM_PASSWORD = 'Gocubsgo617!'

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



with app.app_context():
    db.create_all()


@app.route('/', methods=["GET", "POST"])
def home_page():
    return render_template('index.html')

@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    return render_template('dashboard.html')

@app.route('/create/<post_type>', methods=["GET", "POST"])
def create(post_type):
    if post_type == '2x2':
        form = TwoByTwoForm()
        if form.validate_on_submit():
            try:
                # Get form values
                title = form.title.data
                labels = [
                    form.label1.data,
                    form.label2.data,
                    form.label3.data,
                    form.label4.data
                ]
                music_choice = request.form.get('music', '1')  # Default to chill music
                
                # Generate a unique filename for the video
                video_filename = f"output_{uuid.uuid4().hex}.mp4"
                output_path = os.path.join('static', 'videos', video_filename)
                
                # Ensure the videos directory exists
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Create the video
                from video_creator import create_video
                create_video(title, labels, output_path, music_choice)
                
                # Return the video path to the template
                video_url = url_for('static', filename=f'videos/{video_filename}')
                return render_template('create.html', post_type=post_type, form=form, video_url=video_url)
                
            except Exception as e:
                print(f"Error creating video: {str(e)}")
                flash("An error occurred while creating the video. Please try again.")
                return render_template('create.html', post_type=post_type, form=form)
                
        return render_template('create.html', post_type=post_type, form=form)
    elif post_type == 'more_likely_to':
        #form = MoreLikelyToForm()
        return render_template('create.html', post_type=post_type, form=form)

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

@app.route('/post-to-instagram', methods=['POST'])
@login_required
def post_to_instagram():
    temp_video_path = None
    try:
        video_url = request.form.get('video_url')
        if not video_url:
            print("Error: No video URL provided")
            return jsonify({'error': 'No video URL provided'}), 400

        # Download the video to a temporary file
        print(f"Attempting to download video from: {video_url}")
        response = requests.get(video_url)
        if response.status_code != 200:
            print(f"Error: Failed to download video. Status code: {response.status_code}")
            return jsonify({'error': f'Failed to download video. Status code: {response.status_code}'}), 400

        temp_video_path = f'temp_{uuid.uuid4().hex}.mp4'
        with open(temp_video_path, 'wb') as f:
            f.write(response.content)
        print(f"Video downloaded and saved to: {temp_video_path}")

        # Step 1: Create a media container
        container_url = f'https://graph.facebook.com/v18.0/{INSTAGRAM_BUSINESS_ACCOUNT_ID}/media'
        container_params = {
            'video_url': video_url,
            'caption': 'Created with Social Media Maker',
            'access_token': INSTAGRAM_ACCESS_TOKEN
        }
        
        print("Attempting to create media container")
        print(f"Container URL: {container_url}")
        print(f"Container Params: {container_params}")
        
        container_response = requests.post(container_url, params=container_params)
        print(f"Container Response Status: {container_response.status_code}")
        print(f"Container Response Text: {container_response.text}")
        
        if container_response.status_code != 200:
            print(f"Error: Failed to create media container. Status code: {container_response.status_code}")
            print(f"Response content: {container_response.text}")
            os.remove(temp_video_path)
            return jsonify({'error': f'Failed to create media container. Status code: {container_response.status_code}'}), 400

        try:
            container_data = container_response.json()
            container_id = container_data.get('id')
            if not container_id:
                raise ValueError("No container ID in response")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing container response: {str(e)}")
            print(f"Raw response: {container_response.text}")
            os.remove(temp_video_path)
            return jsonify({'error': 'Invalid response from Instagram API'}), 400

        print(f"Media container created successfully. Container ID: {container_id}")
        
        # Step 2: Check container status
        status_url = f'https://graph.facebook.com/v18.0/{container_id}'
        status_params = {
            'fields': 'status_code',
            'access_token': INSTAGRAM_ACCESS_TOKEN
        }

        # Poll for status
        max_attempts = 10
        for attempt in range(max_attempts):
            print(f"Checking container status. Attempt {attempt + 1}/{max_attempts}")
            status_response = requests.get(status_url, params=status_params)
            print(f"Status Response Status: {status_response.status_code}")
            print(f"Status Response Text: {status_response.text}")
            
            if status_response.status_code != 200:
                print(f"Error: Failed to check container status. Status code: {status_response.status_code}")
                print(f"Response content: {status_response.text}")
                os.remove(temp_video_path)
                return jsonify({'error': f'Failed to check container status. Status code: {status_response.status_code}'}), 400

            try:
                status_data = status_response.json()
                status = status_data.get('status_code')
            except json.JSONDecodeError as e:
                print(f"Error parsing status response: {str(e)}")
                print(f"Raw response: {status_response.text}")
                os.remove(temp_video_path)
                return jsonify({'error': 'Invalid status response from Instagram API'}), 400

            print(f"Current status: {status}")
            if status == 'FINISHED':
                break
            elif status == 'ERROR':
                print("Error: Media container processing failed")
                os.remove(temp_video_path)
                return jsonify({'error': 'Media container processing failed'}), 400
            
            time.sleep(2)  # Wait 2 seconds before checking again

        # Step 3: Publish the media
        publish_url = f'https://graph.facebook.com/v18.0/{INSTAGRAM_BUSINESS_ACCOUNT_ID}/media_publish'
        publish_params = {
            'creation_id': container_id,
            'access_token': INSTAGRAM_ACCESS_TOKEN
        }

        print("Attempting to publish media")
        print(f"Publish URL: {publish_url}")
        print(f"Publish Params: {publish_params}")
        
        publish_response = requests.post(publish_url, params=publish_params)
        print(f"Publish Response Status: {publish_response.status_code}")
        print(f"Publish Response Text: {publish_response.text}")
        
        os.remove(temp_video_path)  # Clean up temporary file
        print(f"Temporary file removed: {temp_video_path}")

        if publish_response.status_code != 200:
            print(f"Error: Failed to publish to Instagram. Status code: {publish_response.status_code}")
            print(f"Response content: {publish_response.text}")
            return jsonify({'error': f'Failed to publish to Instagram. Status code: {publish_response.status_code}'}), 400

        try:
            publish_data = publish_response.json()
            if 'id' not in publish_data:
                raise ValueError("No post ID in response")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing publish response: {str(e)}")
            print(f"Raw response: {publish_response.text}")
            return jsonify({'error': 'Invalid publish response from Instagram API'}), 400

        print("Video posted to Instagram successfully")
        return jsonify({'success': True, 'message': 'Video posted to Instagram successfully'})

    except Exception as e:
        print(f"Error in post_to_instagram: {str(e)}")
        if os.path.exists(temp_video_path):
            os.remove(temp_video_path)
        return jsonify({'error': str(e)}), 500

@app.route('/background_music/<path:filename>')
def serve_background_music(filename):
    print(f"Attempting to serve audio file: {filename}")
    try:
        return send_file(f'background_music/{filename}')
    except Exception as e:
        print(f"Error serving audio file: {str(e)}")
        return str(e), 404

@app.route('/test-instagram-connection', methods=['POST'])
def test_instagram_connection():
    try:
        # Initialize the client with more settings
        cl = Client()
        cl.delay_range = [1, 3]  # Add delay between actions to avoid rate limiting
        
        # Try to load settings from file
        settings_file = 'instagram_settings.json'
        if os.path.exists(settings_file):
            try:
                cl.load_settings(settings_file)
                print("Successfully loaded settings from file")
            except Exception as e:
                print(f"Error loading settings: {str(e)}")
                # If loading fails, we'll try to login normally
        
        # Login to Instagram with more detailed error handling
        try:
            print(f"Attempting to login with username: {INSTAGRAM_USERNAME}")
            cl.login(INSTAGRAM_USERNAME, INSTAGRAM_PASSWORD)
            print("Login successful")
            
            # Save settings after successful login
            cl.dump_settings(settings_file)
            print("Settings saved successfully")
            
            # Test account info retrieval
            account_info = cl.account_info()
            print(f"Account info retrieved: {account_info.username}")
            
        except LoginRequired as e:
            print(f"Login required error: {str(e)}")
            return jsonify({'error': f'Login failed: {str(e)}'}), 401
        except ClientError as e:
            print(f"Client error: {str(e)}")
            return jsonify({'error': f'Client error: {str(e)}'}), 400
        except Exception as e:
            print(f"Unexpected error during login: {str(e)}")
            return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

        # Check if output.mp4 exists
        video_path = 'output.mp4'
        if not os.path.exists(video_path):
            print(f"Video file not found at path: {video_path}")
            return jsonify({'error': 'output.mp4 file not found'}), 400

        # Upload the video
        try:
            print("Attempting to upload video...")
            # Upload the video with a test caption
            media = cl.clip_upload(
                path=video_path,
                caption="Test post from Social Media Maker"
            )
            print(f"Video uploaded successfully. Media ID: {media.pk}")
            
            # Get the media info to confirm it was posted
            media_info = cl.media_info(media.pk)
            print(f"Media info retrieved: {media_info}")
            
            return jsonify({
                'success': True,
                'message': 'Video posted to Instagram successfully',
                'media_id': media.pk,
                'media_url': f'https://instagram.com/p/{media.code}'
            })
            
        except Exception as e:
            print(f"Error uploading video: {str(e)}")
            return jsonify({'error': f'Failed to upload video: {str(e)}'}), 500

    except Exception as e:
        print(f"Unexpected error in test_instagram_connection: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure we always return a JSON response
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5002)




