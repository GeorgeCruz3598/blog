from flask import Flask, render_template, request, flash, redirect, make_response, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "Qu3M1r4$Tu"  

#Inicializar Flask-Login
login_manager = LoginManager() # cargar loginmanager
login_manager.login_view = 'login' #tipo vista login
login_manager.init_app(app) #iniciar login para app

def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

#crear tablas
def init_db():
    conn = get_db_connection()
    conn.execute('''
    create table if not exists users(
      id integer primary key autoincrement,
      username text unique not null,
      password_hash text not null,
      created_at date default (date('now'))
    ); ''')
    
    conn.execute('''
    create table if not exists posts(
      id integer primary key autoincrement,
      content text not null,
      user_id integer not null,
      created_at date default (date('now')),
      foreign key (user_id) references users(id)
    ); ''')
    
    conn.commit()
    conn.close()
    
#clase para manejar usuarios
class User(UserMixin):
    #constructor
    def __init__(self,id,username, password_hash, created_at=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.created_at = created_at        
    #Metodos para recuperar datos de usuario en basado en ID or username desde la BD
     #BY ID
    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        user = conn.execute("select * from users where id=?",(user_id,)).fetchone() 
        conn.close()
        if user: 
            return User(user['id'],user['username'],user['password_hash'],user['created_at']) 
        return None
    #BY USERNAME
    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute("select * from users where username=?",(username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'],user['username'],user['password_hash'],user['created_at']) 
        return None

#Cargar usuario basado en ID
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id) #retorna objeto  con  datos de usuario recuperado de DB

#INICIO
@app.route("/")
def inicio():
    return render_template('index.html')

#REGISTRO DE USUARIOS
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash_pass = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            conn.execute("""insert into users(username,password_hash) 
                         values(?,?);""",(username,hash_pass))
            conn.commit()
            flash("Usuario añadido correctamente. Inicie Sesion","success")
            return redirect(url_for('inicio'))
        except sqlite3.IntegrityError:
            flash("EL usuario ya existe","warning")
        finally:
            conn.close()
    return render_template('register.html')

#Log IN
@app.route('/login',methods=['POST','GET'])
def login():
    if request.method=='POST':
        username = request.form.get('username')
        passwd = request.form.get('passwd')
        
        user = User.get_by_username(username) #objeto user con los attributos de tabla basado en username introducido de login
        if user and check_password_hash(user.password_hash, passwd): #si user.password(recuperado de DB) == passwd (recuperado de login form)
            login_user(user) #  se loguea
            flash('Se ha iniciado session correctamente','success') 
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales no validas','danger')
    return render_template('login.html')

#dashboard
@app.route('/dashboard')
@login_required #protected -> require logged in to go this route
def dashboard():
    return render_template('dashboard.html',username=current_user.username)

#logout
@app.route('/logout')
@login_required
def logout():
    logout_user() #flask-login methods
    flash('Has cerrado session','info')
    return redirect(url_for('inicio'))

if __name__=="__main__":
    init_db()
    app.run(debug=True)
     