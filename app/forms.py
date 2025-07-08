from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo

class RegisterForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(min=4)])
    confirm_password = PasswordField("Подтверждение пароля", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Зарегистрироваться")

class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired()])
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

    