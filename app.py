from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import uuid
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'another-secret-key-here'  # Different from SECRET_KEY

# Initialize CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)

# Add CSRF token to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Ensure CSRF token is included in all responses
@app.after_request
def add_csrf_token(response):
    csrf_token = generate_csrf()
    response.set_cookie('csrf_token', csrf_token)
    return response

# User data storage
USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, user_data):
        self.id = username
        self.password_hash = user_data.get('password')
        self.accounts = user_data.get('accounts', [])
        
    def get_account(self, account_id):
        """Get a specific account by ID"""
        for account in self.accounts:
            if account.get('id') == account_id:
                return account
        return None
    
    def add_account(self, account_data):
        """Add a new game account"""
        if not any(acc.get('email') == account_data.get('email') for acc in self.accounts):
            account_data['id'] = str(uuid.uuid4())
            account_data['created_at'] = datetime.now().isoformat()
            self.accounts.append(account_data)
            return True
        return False
    
    def update_account(self, account_id, account_data):
        """Update an existing game account"""
        for i, account in enumerate(self.accounts):
            if account.get('id') == account_id:
                account_data['id'] = account_id
                account_data['updated_at'] = datetime.now().isoformat()
                self.accounts[i] = {**account, **account_data}
                return True
        return False
    
    def delete_account(self, account_id):
        """Delete a game account"""
        for i, account in enumerate(self.accounts):
            if account.get('id') == account_id:
                del self.accounts[i]
                return True
        return False

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(username):
    users = load_users()
    if username in users:
        user_data = users[username]
        return User(username, user_data)
    return None

# Template filters
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    try:
        return value.strftime(format)
    except:
        return value

@app.template_filter('to_datetime')
def to_datetime(value):
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return value

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = load_users()
        
        if username in users and users[username]['password'].startswith('pbkdf2:sha256:') and check_password_hash(users[username]['password'], password):
            user_data = users[username]
            user = User(
                username=username,
                user_data=user_data
            )
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = load_users()
        
        if username in users:
            flash('اسم المستخدم موجود مسبقاً', 'error')
        else:
            users[username] = {
                'password': generate_password_hash(password, method='pbkdf2:sha256'),
                'accounts': []
            }
            save_users(users)
            flash('تم التسجيل بنجاح! يرجى تسجيل الدخول', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # No need to load users again since current_user already has the data
    return render_template('dashboard.html')

@app.route('/bot_setup', methods=['GET', 'POST'])
@login_required
def bot_setup():
    if request.method == 'POST':
        # Get subscription end date (default to 30 days from now if not provided)
        subscription_days = int(request.form.get('subscription_days', 30))
        subscription_end = (datetime.now() + timedelta(days=subscription_days)).isoformat()
        
        account_data = {
            'email': request.form.get('email'),
            'password': request.form.get('password'),
            'phone': request.form.get('phone'),
            'igg_id': request.form.get('igg_id'),
            'status': 'active',
            'created_at': datetime.now().isoformat(),
            'subscription_start': datetime.now().isoformat(),
            'subscription_end': subscription_end,
            'subscription_days': subscription_days
        }
        
        users = load_users()
        if current_user.id in users:
            # Check if account with this email already exists
            if any(acc.get('email') == account_data['email'] for acc in users[current_user.id].get('accounts', [])):
                flash('هذا الحساب مسجل مسبقاً', 'error')
                return redirect(url_for('dashboard'))
                
            # Add the new account
            if 'accounts' not in users[current_user.id]:
                users[current_user.id]['accounts'] = []
                
            users[current_user.id]['accounts'].append({
                'id': str(uuid.uuid4()),
                **account_data
            })
            
            save_users(users)
            
            # Update current_user object
            current_user.accounts = users[current_user.id]['accounts']
            
            flash('تمت إضافة الحساب بنجاح', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('bot_setup.html')

@app.route('/account/delete/<account_id>', methods=['POST'])
@login_required
def delete_account(account_id):
    # Check CSRF token
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or csrf_token != request.cookies.get('csrf_token'):
        flash('رمز التحقق غير صالح', 'error')
        return redirect(url_for('dashboard'))
        
    users = load_users()
    if current_user.id in users:
        if current_user.delete_account(account_id):
            users[current_user.id]['accounts'] = current_user.accounts
            save_users(users)
            flash('تم حذف الحساب بنجاح', 'success')
        else:
            flash('لم يتم العثور على الحساب', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/account/update/<account_id>', methods=['POST'])
@login_required
def update_account(account_id):
    users = load_users()
    if current_user.id not in users:
        flash('حدث خطأ في تحميل بيانات المستخدم', 'error')
        return redirect(url_for('dashboard'))
    
    # Find the account
    account = None
    for i, acc in enumerate(users[current_user.id].get('accounts', [])):
        if acc.get('id') == account_id:
            # Update account data
            users[current_user.id]['accounts'][i].update({
                'email': request.form.get('email'),
                'phone': request.form.get('phone'),
                'igg_id': request.form.get('igg_id'),
                'status': request.form.get('status', 'active'),
                'updated_at': datetime.now().isoformat()
            })
            
            # Update password if provided
            if request.form.get('password'):
                users[current_user.id]['accounts'][i]['password'] = request.form.get('password')
            
            # Save the changes
            save_users(users)
            
            # Update current_user object
            current_user.accounts = users[current_user.id]['accounts']
            
            flash('تم تحديث الحساب بنجاح', 'success')
            return redirect(url_for('dashboard'))
    
    flash('لم يتم العثور على الحساب', 'error')
    return redirect(url_for('dashboard'))

@app.route('/daily_tasks/<account_id>', methods=['GET', 'POST'])
@login_required
def daily_tasks(account_id):
    users = load_users()
    if current_user.id not in users:
        flash('حدث خطأ في تحميل بيانات المستخدم', 'error')
        return redirect(url_for('dashboard'))
    
    # Find the account
    account = None
    for acc in users[current_user.id].get('accounts', []):
        if acc.get('id') == account_id:
            account = acc
            break
    
    if not account:
        flash('الحساب غير موجود', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Initialize tasks if not exists
        if 'tasks' not in account:
            account['tasks'] = {}
        
        # Get the list of completed tasks from the form
        completed_tasks = request.form.getlist('tasks')
        
        # Update task status
        task_names = ['30', '70', '120', '180', '260', '340', '420', '500']
        for task_id in task_names:
            account['tasks'][task_id] = task_id in completed_tasks
        
        # Save the updated account
        save_users(users)
        
        # Update current_user object
        current_user.accounts = users[current_user.id]['accounts']
        
        flash('تم تحديث المهام بنجاح', 'success')
        return redirect(url_for('daily_tasks', account_id=account_id))
    
    return render_template('daily_tasks.html', account=account)

@app.route('/castle_settings/<account_id>', methods=['GET', 'POST'])
@login_required
def castle_settings(account_id):
    users = load_users()
    if current_user.id not in users:
        flash('حدث خطأ في تحميل بيانات المستخدم', 'error')
        return redirect(url_for('dashboard'))
    
    # Find the account
    account = None
    for acc in users[current_user.id].get('accounts', []):
        if acc.get('id') == account_id:
            account = acc
            break
    
    if not account:
        flash('الحساب غير موجود', 'error')
        return redirect(url_for('dashboard'))
    
    # Define all possible tasks with their default values
    all_tasks = [
        'ads', 'treasure_hunter', 'vip_hunt', 'recruit_soldiers',
        'champion_platform', 'daily_login', 'vip_box_old', 'vip_box_new',
        'shop_box', 'daily_purchase_box', 'weekly_cards', 'donate_pearls',
        'alliance_donation', 'alliance_mission', 'likes'
    ]
    
    if request.method == 'POST':
        # Initialize tasks if not exists
        if 'tasks' not in account:
            account['tasks'] = {}
        
        # Update task status for all possible tasks
        for task_id in all_tasks:
            account['tasks'][task_id] = task_id in request.form.getlist('tasks')
        
        # Handle free wish selection
        free_wish = request.form.get('free_wish')
        if free_wish in ['wood', 'wheat', 'iron']:
            account['tasks']['free_wish'] = free_wish
        
        # Save the updated account
        save_users(users)
        
        # Update current_user object
        current_user.accounts = users[current_user.id]['accounts']
        
        flash('تم تحديث إعدادات القلعة بنجاح', 'success')
        return redirect(url_for('castle_settings', account_id=account_id))
    
    # Initialize any missing tasks with False
    if 'tasks' not in account:
        account['tasks'] = {}
    
    # Ensure all tasks exist in the account's tasks
    for task_id in all_tasks:
        if task_id not in account['tasks']:
            account['tasks'][task_id] = False
    
    # Ensure free_wish exists
    if 'free_wish' not in account['tasks']:
        account['tasks']['free_wish'] = ''
    
    return render_template('castle_settings.html', account=account)

@app.route('/call_formation/<account_id>/delete-building/<building_id>', methods=['POST'])
@login_required
def delete_building(account_id, building_id):
    # Get CSRF token from form data or JSON
    csrf_token = None
    if request.is_json:
        data = request.get_json()
        csrf_token = data.get('csrf_token')
    else:
        csrf_token = request.form.get('csrf_token')
    
    # Verify CSRF token
    cookie_token = request.cookies.get('csrf_token')
    if not csrf_token or csrf_token != cookie_token:
        return jsonify({
            'status': 'error', 
            'message': 'رمز التحقق غير صالح',
            'csrf_required': True
        }), 403
    
    try:
        users = load_users()
        if current_user.id not in users:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Find the account
        account = None
        account_index = -1
        for i, acc in enumerate(users[current_user.id].get('accounts', [])):
            if acc.get('id') == account_id:
                account = acc
                account_index = i
                break
        
        if not account:
            return jsonify({'status': 'error', 'message': 'Account not found'}), 404
        
        if 'call_formation' not in account or 'buildings' not in account['call_formation']:
            return jsonify({'status': 'error', 'message': 'No buildings found'}), 404
        
        # Find and remove the building
        buildings = account['call_formation']['buildings']
        initial_count = len(buildings)
        account['call_formation']['buildings'] = [b for b in buildings if b.get('id') != building_id]
        
        if len(account['call_formation']['buildings']) == initial_count:
            return jsonify({'status': 'error', 'message': 'Building not found'}), 404
        
        # Save the updated account
        users[current_user.id]['accounts'][account_index] = account
        save_users(users)
        
        return jsonify({
            'status': 'success',
            'message': 'تم حذف المبنى بنجاح',
            'csrf_token': generate_csrf()
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'حدث خطأ أثناء حذف المبنى: {str(e)}'
        }), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    app.run(debug=True)
