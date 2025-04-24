from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, TextAreaField, TelField, EmailField, BooleanField, SelectMultipleField
from wtforms.validators import DataRequired, NumberRange, Regexp, Email, URL, Length, EqualTo
from flask_ckeditor import CKEditorField


class BaseForm(FlaskForm):
    """Base form class with common functionality"""
    def get_field_data(self):
        return {field.name: field.data for field in self if field.name != 'submit'}

class AuthForms:
    """Group of authentication-related forms"""
    class RegisterForm(BaseForm):
        email = StringField("Email", validators=[DataRequired(), Email()])
        password = PasswordField("Password", validators=[DataRequired(), Length(min=8, message="Password must be at least 8 characters long")])
        confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
        name = StringField("Name", validators=[DataRequired(), Length(min=2, max=100, message="Name must be between 2 and 100 characters")])
        submit = SubmitField("Sign Me Up!")

    class LoginForm(BaseForm):
        email = StringField("Email", validators=[DataRequired(), Email()])
        password = PasswordField("Password", validators=[DataRequired()])
        submit = SubmitField("Let Me In!")

    class ChangePasswordForm(BaseForm):
        email = StringField("Email", validators=[DataRequired(), Email()])
        password = PasswordField("Password", validators=[DataRequired()])
        new_password = PasswordField("New Password", validators=[DataRequired()])
        submit = SubmitField("Change Password")

    class ForgotPasswordForm(FlaskForm):
        email = StringField('Email', validators=[DataRequired(), Email()])
        submit = SubmitField('Send Reset Link')

    class ResetPasswordForm(FlaskForm):
        password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
        confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
        submit = SubmitField('Reset Password')


class FeedbackForm(BaseForm):
    """Feedback form"""
    title = StringField("Short Title", validators=[DataRequired()])
    feedback = TextAreaField("Feedback", validators=[DataRequired()], 
                           description="Please provide your detailed feedback")
    submit = SubmitField("Provide Feedback")