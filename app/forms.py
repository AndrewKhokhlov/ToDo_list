from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from app.models import User

class RegisterForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email(message='Некорректный адрес электронной почты')])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(min=4)])
    confirm_password = PasswordField("Подтверждение пароля", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Зарегистрироваться")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Этот адрес электронной почты уже зарегистрирован.')

class LoginForm(FlaskForm):
    email = StringField("Почта", validators=[DataRequired(), Email()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")

class TaskForm(FlaskForm):
    title   = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Текст задачи', validators=[DataRequired()])
    submit  = SubmitField('Сохранить')

class DeleteTaskForm(FlaskForm):
    submit = SubmitField('Удалить задачу')

class EditTaskForm(FlaskForm):
    title   = StringField('Заголовок', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Текст задачи', validators=[DataRequired()])
    submit  = SubmitField('Сохранить изменения')

class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Сохранить изменения')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        # Проверка, изменилось ли имя пользователя и существует ли оно уже
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user:
                raise ValidationError('Это имя пользователя уже занято.')

    def validate_email(self, email):
        # Проверка, изменился ли email и существует ли он уже
        if email.data != self.original_email:
            user = User.query.filter_by(email=self.email.data).first()
            if user:
                raise ValidationError('Этот email уже зарегистрирован.')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Текущий пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[DataRequired(), Length(min=6, message='Пароль должен быть не менее 6 символов')]) # Пример валидации длины
    confirm_new_password = PasswordField(
        'Повторите новый пароль', validators=[DataRequired(), EqualTo('new_password', message='Пароли должны совпадать')])
    submit = SubmitField('Изменить пароль')