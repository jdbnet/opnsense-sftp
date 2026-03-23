"""
Flask application for OPNsense backup management via SFTP.
"""
import os
from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify, flash
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pathlib import Path
from datetime import datetime, timedelta
import threading
import time
from dotenv import load_dotenv
import pyotp

from database import Database
from ssh_keys import SSHKeyManager
from sftp_server import SFTPThreadedServer
from logger_config import setup_logging, get_logger

# Load environment variables
load_dotenv()

# Setup logging
setup_logging()
logger = get_logger(__name__)

def get_version():
    return os.getenv('APP_VERSION', 'dev')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-secret-key-in-production')

# Get version for templates
app_version = get_version()

# Make version available to all templates
@app.context_processor
def inject_version():
    return dict(version=app_version)

# Initialize components
db = Database()
ssh_key_manager = SSHKeyManager()
sftp_server = SFTPThreadedServer(
    host=os.getenv('SFTP_HOST', '0.0.0.0'),
    port=int(os.getenv('SFTP_PORT', '2222')),
    database=db,
    ssh_key_manager=ssh_key_manager,
    backups_dir=os.getenv('BACKUPS_DIR', 'backups')
)

# Initialize database on startup
try:
    db.init_database()
    # Create default admin user if it doesn't exist
    default_user = db.get_user_by_username('admin')
    if not default_user:
        default_password = os.getenv('ADMIN_PASSWORD', 'admin')
        db.create_user('admin', generate_password_hash(default_password), is_admin=True)
        logger.warning("Created default admin user (password: 'admin' - CHANGE THIS!)")
    elif not default_user.get('is_admin'):
        db.update_user_admin(default_user['id'], True)
        logger.info("Updated default admin user with admin privileges")
    logger.info("Database initialized successfully")
except Exception as e:
    logger.error(f"Database initialization failed: {e}")

# Start SFTP server
try:
    sftp_server.start()
    logger.info(f"SFTP server started on {sftp_server.host}:{sftp_server.port}")
except Exception as e:
    logger.error(f"Failed to start SFTP server: {e}")


def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Get current logged-in user from database."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.get_user_by_id(user_id)


def _sign_in_user(user):
    """Set session keys for authenticated user."""
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = bool(user.get('is_admin'))


@app.route('/')
def index():
    """Redirect to dashboard if logged in, otherwise to login."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if session.get('totp_pending_user_id'):
        return redirect(url_for('login_totp'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = db.get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            if user.get('totp_enabled'):
                # Step 1 complete: require second factor on separate page.
                session.clear()
                session['totp_pending_user_id'] = user['id']
                return redirect(url_for('login_totp'))

            session.clear()
            _sign_in_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')


@app.route('/login/totp', methods=['GET', 'POST'])
def login_totp():
    """Second-factor login page for users with TOTP enabled."""
    pending_user_id = session.get('totp_pending_user_id')
    if not pending_user_id:
        return redirect(url_for('login'))

    user = db.get_user_by_id(pending_user_id)
    if not user or not user.get('totp_enabled'):
        session.pop('totp_pending_user_id', None)
        flash('TOTP session expired. Please log in again.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = (request.form.get('otp_code') or '').strip().replace(' ', '')
        if not otp_code:
            flash('TOTP code is required', 'error')
            return render_template('login_totp.html', username=user['username'])

        totp_secret = user.get('totp_secret')
        if not totp_secret:
            session.pop('totp_pending_user_id', None)
            flash('TOTP is enabled but no secret is configured. Contact an admin.', 'error')
            return redirect(url_for('login'))

        is_valid = pyotp.TOTP(totp_secret).verify(otp_code, valid_window=1)
        if not is_valid:
            flash('Invalid TOTP code', 'error')
            return render_template('login_totp.html', username=user['username'])

        session.clear()
        _sign_in_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login_totp.html', username=user['username'])


@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Manage current user's profile: username, password, and TOTP."""
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_username':
            new_username = (request.form.get('new_username') or '').strip()
            if not new_username:
                flash('Username is required', 'error')
                return redirect(url_for('profile'))

            existing = db.get_user_by_username(new_username)
            if existing and existing['id'] != user['id']:
                flash('That username is already in use', 'error')
                return redirect(url_for('profile'))

            if db.update_user_username(user['id'], new_username):
                session['username'] = new_username
                flash('Username updated successfully', 'success')
            else:
                flash('Failed to update username', 'error')
            return redirect(url_for('profile'))

        if action == 'update_password':
            current_password = request.form.get('current_password') or ''
            new_password = request.form.get('new_password') or ''
            confirm_password = request.form.get('confirm_password') or ''

            if not check_password_hash(user['password_hash'], current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
            if len(new_password) < 8:
                flash('New password must be at least 8 characters', 'error')
                return redirect(url_for('profile'))
            if new_password != confirm_password:
                flash('New password and confirmation do not match', 'error')
                return redirect(url_for('profile'))

            if db.update_user_password(user['id'], generate_password_hash(new_password)):
                flash('Password updated successfully', 'success')
            else:
                flash('Failed to update password', 'error')
            return redirect(url_for('profile'))

        if action == 'generate_totp_secret':
            secret = pyotp.random_base32()
            if db.update_user_totp(user['id'], secret, False):
                flash('Generated a new TOTP secret. Verify a code to enable TOTP.', 'success')
            else:
                flash('Failed to generate TOTP secret', 'error')
            return redirect(url_for('profile'))

        if action == 'enable_totp':
            otp_code = (request.form.get('otp_code') or '').strip().replace(' ', '')
            fresh_user = db.get_user_by_id(user['id'])
            totp_secret = fresh_user.get('totp_secret') if fresh_user else None

            if not totp_secret:
                flash('No TOTP secret found. Generate one first.', 'error')
                return redirect(url_for('profile'))

            if not pyotp.TOTP(totp_secret).verify(otp_code, valid_window=1):
                flash('Invalid TOTP code. Please try again.', 'error')
                return redirect(url_for('profile'))

            if db.update_user_totp(user['id'], totp_secret, True):
                flash('TOTP enabled for your account.', 'success')
            else:
                flash('Failed to enable TOTP', 'error')
            return redirect(url_for('profile'))

        if action == 'disable_totp':
            if db.update_user_totp(user['id'], None, False):
                flash('TOTP disabled.', 'success')
            else:
                flash('Failed to disable TOTP', 'error')
            return redirect(url_for('profile'))

        flash('Unknown action', 'error')
        return redirect(url_for('profile'))

    user = get_current_user()
    if user.get('totp_secret'):
        totp_uri = pyotp.TOTP(user['totp_secret']).provisioning_uri(
            name=user['username'],
            issuer_name='OPNsense Backup Manager',
        )
    else:
        totp_uri = None
    return render_template('profile.html', user=user, totp_uri=totp_uri)


@app.route('/users')
@login_required
@admin_required
def users():
    """List and manage users."""
    all_users = db.get_all_users()
    return render_template('users.html', users=all_users)


@app.route('/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Create a user account."""
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''
    is_admin = bool(request.form.get('is_admin'))

    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('users'))
    if len(password) < 8:
        flash('Password must be at least 8 characters', 'error')
        return redirect(url_for('users'))
    if db.get_user_by_username(username):
        flash('Username already exists', 'error')
        return redirect(url_for('users'))

    user_id = db.create_user(username, generate_password_hash(password), is_admin=is_admin)
    if user_id:
        flash('User created successfully', 'success')
    else:
        flash('Failed to create user', 'error')
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_user_admin(user_id):
    """Toggle admin role for a user."""
    target_user = db.get_user_by_id(user_id)
    if not target_user:
        flash('User not found', 'error')
        return redirect(url_for('users'))

    all_users = db.get_all_users()
    admin_count = sum(1 for u in all_users if u.get('is_admin'))

    new_is_admin = not bool(target_user.get('is_admin'))
    if not new_is_admin and admin_count <= 1:
        flash('Cannot remove admin role from the last admin user', 'error')
        return redirect(url_for('users'))

    if target_user['id'] == session.get('user_id') and not new_is_admin:
        flash('You cannot remove your own admin role', 'error')
        return redirect(url_for('users'))

    if db.update_user_admin(user_id, new_is_admin):
        flash('User admin role updated', 'success')
    else:
        flash('Failed to update user admin role', 'error')
    return redirect(url_for('users'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user account."""
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('users'))

    target_user = db.get_user_by_id(user_id)
    if not target_user:
        flash('User not found', 'error')
        return redirect(url_for('users'))

    all_users = db.get_all_users()
    admin_count = sum(1 for u in all_users if u.get('is_admin'))
    if target_user.get('is_admin') and admin_count <= 1:
        flash('Cannot delete the last admin user', 'error')
        return redirect(url_for('users'))

    if db.delete_user(user_id):
        flash('User deleted successfully', 'success')
    else:
        flash('Failed to delete user', 'error')
    return redirect(url_for('users'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard."""
    instances = db.get_all_instances()
    all_backups = db.get_all_backups()
    total_backup_size = sum((backup.get('file_size') or 0) for backup in all_backups)
    
    # Add instance info to each backup
    for backup in all_backups:
        instance = db.get_instance_by_id(backup['instance_id'])
        if instance:
            backup['instance_name'] = instance['name']
            backup['instance_identifier'] = instance['identifier']
    
    return render_template(
        'dashboard.html',
        instances=instances,
        backups=all_backups,
        sftp_server=sftp_server,
        total_backup_size=total_backup_size
    )


@app.route('/instances')
@login_required
def instances():
    """List all OPNsense instances."""
    instances = db.get_all_instances()
    
    # Get SSH keys for each instance
    for instance in instances:
        ssh_key = db.get_ssh_key_by_key_id(instance['ssh_key_id'])
        if ssh_key:
            instance['public_key'] = ssh_key['public_key']
        else:
            instance['public_key'] = None
    
    return render_template('instances.html', instances=instances)


@app.route('/instances/new', methods=['GET', 'POST'])
@login_required
def new_instance():
    """Create a new OPNsense instance."""
    if request.method == 'POST':
        name = request.form.get('name')
        identifier = request.form.get('identifier')
        description = request.form.get('description', '')
        
        if not name or not identifier:
            flash('Name and identifier are required', 'error')
            return render_template('new_instance.html')
        
        # Check if identifier already exists
        existing = db.get_instance_by_identifier(identifier)
        if existing:
            flash('An instance with this identifier already exists', 'error')
            return render_template('new_instance.html')
        
        # Generate SSH key pair
        key_id = ssh_key_manager.generate_key_id()
        private_key_path, public_key = ssh_key_manager.generate_key_pair(key_id)
        
        # Create instance
        instance_id = db.create_instance(name, identifier, key_id, description)
        
        if not instance_id:
            flash('Failed to create instance', 'error')
            return render_template('new_instance.html')
        
        # Save SSH key to database
        db.save_ssh_key(key_id, instance_id, public_key, private_key_path)
        
        flash('Instance created successfully!', 'success')
        return redirect(url_for('instance_detail', instance_id=instance_id))
    
    return render_template('new_instance.html')


@app.route('/instances/<int:instance_id>')
@login_required
def instance_detail(instance_id):
    """View instance details and backups."""
    instance = db.get_instance_by_id(instance_id)
    if not instance:
        flash('Instance not found', 'error')
        return redirect(url_for('instances'))
    
    ssh_key = db.get_ssh_key_by_key_id(instance['ssh_key_id'])
    if not ssh_key:
        flash('SSH key not found for this instance', 'error')
        return redirect(url_for('instances'))
    
    backups = db.get_backups_for_instance(instance_id)
    
    # Get SFTP connection info
    sftp_host = os.getenv('SFTP_PUBLIC_HOST', request.host.split(':')[0])
    # Use public port if configured (e.g., NodePort), otherwise use internal port
    sftp_port = int(os.getenv('SFTP_PUBLIC_PORT', sftp_server.port))
    
    # Build SFTP URI for OPNsense with instance identifier in path
    # Format: sftp://lan@host:port//lan
    if sftp_port == 22:
        sftp_uri = f"sftp://{instance['identifier']}@{sftp_host}//{instance['identifier']}"
    else:
        sftp_uri = f"sftp://{instance['identifier']}@{sftp_host}:{sftp_port}//{instance['identifier']}"
    
    # Load private key for download
    private_key_content = ssh_key_manager.load_private_key(instance['ssh_key_id'])
    
    return render_template('instance_detail.html', 
                         instance=instance, 
                         ssh_key=ssh_key,
                         backups=backups,
                         sftp_host=sftp_host,
                         sftp_port=sftp_port,
                         sftp_uri=sftp_uri,
                         private_key_content=private_key_content.decode('utf-8') if private_key_content else None)


@app.route('/backups')
@login_required
def backups():
    """List all backups with pagination and filtering."""
    all_backups = db.get_all_backups()
    
    # Add instance info to each backup
    instances_map = {}
    for backup in all_backups:
        if backup['instance_id'] not in instances_map:
            instance = db.get_instance_by_id(backup['instance_id'])
            instances_map[backup['instance_id']] = instance
        
        instance = instances_map.get(backup['instance_id'])
        if instance:
            backup['instance_name'] = instance['name']
            backup['instance_identifier'] = instance['identifier']
    
    # Get unique instances for filter dropdown
    all_instances = []
    seen_ids = set()
    for backup in all_backups:
        instance_id = backup['instance_id']
        if instance_id not in seen_ids and backup.get('instance_name'):
            all_instances.append({
                'id': instance_id,
                'name': backup['instance_name'],
                'identifier': backup['instance_identifier']
            })
            seen_ids.add(instance_id)
    
    # Sort instances by name
    all_instances.sort(key=lambda x: x['name'])
    
    # Get filter parameter from query string
    filter_instance_id = request.args.get('instance_id', type=int)
    
    # Filter backups if instance filter is applied
    if filter_instance_id:
        filtered_backups = [b for b in all_backups if b['instance_id'] == filter_instance_id]
    else:
        filtered_backups = all_backups
    
    # Sort by upload date descending (newest first)
    filtered_backups.sort(key=lambda x: x['uploaded_at'] or datetime.min, reverse=True)
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10
    total_backups = len(filtered_backups)
    total_pages = (total_backups + per_page - 1) // per_page
    
    # Ensure page is valid
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Get backups for current page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_backups = filtered_backups[start_idx:end_idx]
    
    return render_template('backups.html', 
                         backups=paginated_backups,
                         all_instances=all_instances,
                         current_page=page,
                         total_pages=total_pages,
                         total_backups=total_backups,
                         filter_instance_id=filter_instance_id,
                         per_page=per_page)


@app.route('/backups/<int:backup_id>/download')
@login_required
def download_backup(backup_id):
    """Download a backup file."""
    all_backups = db.get_all_backups()
    backup = next((b for b in all_backups if b['id'] == backup_id), None)
    
    if not backup:
        flash('Backup not found', 'error')
        return redirect(url_for('backups'))
    
    file_path = Path(backup['file_path'])
    if not file_path.exists():
        flash('Backup file not found on disk', 'error')
        return redirect(url_for('backups'))
    
    return send_file(
        str(file_path),
        as_attachment=True,
        download_name=backup['filename']
    )


@app.route('/instances/<int:instance_id>/download-key')
@login_required
def download_private_key(instance_id):
    """Download the private key for an instance."""
    instance = db.get_instance_by_id(instance_id)
    if not instance:
        flash('Instance not found', 'error')
        return redirect(url_for('instances'))
    
    private_key_content = ssh_key_manager.load_private_key(instance['ssh_key_id'])
    if not private_key_content:
        flash('Private key not found', 'error')
        return redirect(url_for('instance_detail', instance_id=instance_id))
    
    # Create a response with the private key
    from flask import Response
    response = Response(
        private_key_content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename="{instance["identifier"]}_private_key"'
        }
    )
    return response


@app.route('/backups/<int:backup_id>/delete', methods=['POST'])
@login_required
def delete_backup(backup_id):
    """Delete a backup."""
    all_backups = db.get_all_backups()
    backup = next((b for b in all_backups if b['id'] == backup_id), None)
    
    if not backup:
        flash('Backup not found', 'error')
        return redirect(url_for('backups'))
    
    file_path = Path(backup['file_path'])
    if file_path.exists():
        try:
            file_path.unlink()
        except Exception as e:
            flash(f'Error deleting file: {e}', 'error')
            return redirect(url_for('backups'))
    
    # Delete from database
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM backups WHERE id = %s", (backup_id,))
            conn.commit()
            cursor.close()
    except Exception as e:
        flash(f'Error deleting backup record: {e}', 'error')
        return redirect(url_for('backups'))
    
    flash('Backup deleted successfully', 'success')
    return redirect(url_for('backups'))


def prune_backups(
    *,
    scope_type: str,
    scope_instance_id: int | None,
    keep_days: int | None,
    keep_count: int | None,
) -> dict:
    """
    Prune backups by retention rules.

    - keep_days: delete backups older than (now - keep_days)
    - keep_count: keep N newest backups per instance
    """
    if (keep_days is None and keep_count is None) or (keep_days is not None and keep_count is not None):
        raise ValueError("Exactly one of keep_days or keep_count must be provided.")

    if scope_type not in {"all", "instance"}:
        raise ValueError("scope_type must be 'all' or 'instance'.")

    instances = []
    if scope_type == "instance":
        if not scope_instance_id:
            raise ValueError("scope_instance_id must be provided when scope_type is 'instance'.")
        instance = db.get_instance_by_id(scope_instance_id)
        if not instance:
            return {"deleted_backups": 0, "deleted_files": 0, "skipped_files": 0, "errors": 1}
        instances = [instance]
    else:
        instances = db.get_all_instances()

    now = datetime.now()
    cutoff = (now - timedelta(days=keep_days)) if keep_days is not None else None

    backups_marked_for_deletion: list[dict] = []
    for instance in instances:
        backups = db.get_backups_for_instance(instance["id"])

        if keep_days is not None:
            # db query orders by uploaded_at DESC, but for "older than" it's fine to just filter.
            for backup in backups:
                uploaded_at = backup.get("uploaded_at")
                if uploaded_at is None or uploaded_at < cutoff:
                    backups_marked_for_deletion.append(backup)
        else:
            # backups are already sorted DESC; keep first N, prune the rest.
            backups_marked_for_deletion.extend(backups[keep_count:])

    if not backups_marked_for_deletion:
        return {"deleted_backups": 0, "deleted_files": 0, "skipped_files": 0, "errors": 0}

    deleted_files = 0
    skipped_files = 0
    db_ids_to_delete: list[int] = []

    for backup in backups_marked_for_deletion:
        file_path = Path(backup["file_path"])
        try:
            if file_path.exists():
                file_path.unlink()
                deleted_files += 1
            else:
                # Stale DB rows are still safe to remove.
                skipped_files += 1
            db_ids_to_delete.append(backup["id"])
        except Exception as e:
            skipped_files += 1
            logger.error(f"Failed deleting backup file {file_path}: {e}", exc_info=True)

    deleted_backups = db.delete_backups_by_ids(db_ids_to_delete)
    return {
        "deleted_backups": deleted_backups,
        "deleted_files": deleted_files,
        "skipped_files": skipped_files,
        "errors": 0,
    }


@app.route("/backups/prune", methods=["GET"])
@login_required
def prune_page():
    """Backup pruning manual runner + automated retention settings."""
    instances = db.get_all_instances()
    prune_settings = db.get_backup_prune_settings()
    return render_template("prune.html", instances=instances, prune_settings=prune_settings)


@app.route("/backups/prune/run", methods=["POST"])
@login_required
def prune_run():
    """Run a manual prune based on form criteria."""
    if not request.form.get("confirm_prune"):
        flash("Confirmation required. Check the confirmation box to prune backups.", "error")
        return redirect(url_for("prune_page"))

    scope_type = request.form.get("scope_type", "all")
    scope_instance_id = request.form.get("scope_instance_id", type=int)

    keep_mode = request.form.get("keep_mode")
    keep_days = None
    keep_count = None

    if keep_mode == "days":
        keep_days = request.form.get("keep_days", type=int)
    elif keep_mode == "count":
        keep_count = request.form.get("keep_count", type=int)
    else:
        flash("Invalid keep mode. Choose either 'Days' or 'Count'.", "error")
        return redirect(url_for("prune_page"))

    if scope_type == "instance" and not scope_instance_id:
        flash("Please select an instance when pruning a single instance.", "error")
        return redirect(url_for("prune_page"))

    if keep_days is not None and keep_days < 1:
        flash("Keep days must be >= 1.", "error")
        return redirect(url_for("prune_page"))
    if keep_count is not None and keep_count < 1:
        flash("Keep count must be >= 1.", "error")
        return redirect(url_for("prune_page"))

    try:
        result = prune_backups(
            scope_type=scope_type,
            scope_instance_id=scope_instance_id,
            keep_days=keep_days,
            keep_count=keep_count,
        )
    except Exception as e:
        logger.error(f"Manual prune failed: {e}", exc_info=True)
        flash(f"Prune failed: {e}", "error")
        return redirect(url_for("prune_page"))

    flash(
        f"Prune complete. Deleted {result['deleted_backups']} backup records. "
        f"Deleted {result['deleted_files']} files.",
        "success",
    )
    return redirect(url_for("prune_page"))


@app.route("/backups/prune/settings", methods=["POST"])
@login_required
def prune_settings():
    """Update automated pruning settings (and optionally run immediately)."""
    enabled = bool(request.form.get("enabled"))

    scope_type = request.form.get("scope_type", "all")
    scope_instance_id = request.form.get("scope_instance_id", type=int)
    if scope_type == "all":
        scope_instance_id = None

    keep_mode = request.form.get("keep_mode")
    keep_days = None
    keep_count = None

    if keep_mode == "days":
        keep_days = request.form.get("keep_days", type=int)
    elif keep_mode == "count":
        keep_count = request.form.get("keep_count", type=int)
    else:
        flash("Invalid keep mode. Choose either 'Days' or 'Count'.", "error")
        return redirect(url_for("prune_page"))

    interval_hours = request.form.get("interval_hours", type=int) or 24
    if interval_hours < 1:
        interval_hours = 24
    interval_seconds = interval_hours * 3600

    if enabled and scope_type == "instance" and not scope_instance_id:
        flash("Please select an instance for automated pruning.", "error")
        return redirect(url_for("prune_page"))

    if keep_days is not None and keep_days < 1:
        flash("Keep days must be >= 1.", "error")
        return redirect(url_for("prune_page"))
    if keep_count is not None and keep_count < 1:
        flash("Keep count must be >= 1.", "error")
        return redirect(url_for("prune_page"))

    db.upsert_backup_prune_settings(
        enabled=enabled,
        scope_type=scope_type,
        scope_instance_id=scope_instance_id,
        keep_days=keep_days if enabled else None,
        keep_count=keep_count if enabled else None,
        interval_seconds=interval_seconds,
    )

    # Optional: run immediately.
    if request.form.get("action") == "run_now" and enabled:
        try:
            prune_backups(
                scope_type=scope_type,
                scope_instance_id=scope_instance_id,
                keep_days=keep_days,
                keep_count=keep_count,
            )
            db.set_backup_prune_last_run_at(datetime.now())
        except Exception as e:
            logger.error(f"Run-now prune failed: {e}", exc_info=True)
            flash(f"Saved settings, but run now failed: {e}", "error")
            return redirect(url_for("prune_page"))

        flash("Saved settings and ran prune now.", "success")
        return redirect(url_for("prune_page"))

    flash("Automated prune settings saved.", "success")
    return redirect(url_for("prune_page"))


def _auto_prune_loop():
    """Background worker that periodically prunes backups based on stored settings."""
    while True:
        try:
            settings = db.get_backup_prune_settings()
            enabled = bool(settings.get("enabled"))
            interval_seconds = int(settings.get("interval_seconds") or 86400)

            if enabled:
                keep_days = settings.get("keep_days")
                keep_count = settings.get("keep_count")
                scope_type = settings.get("scope_type") or "all"
                scope_instance_id = settings.get("scope_instance_id")

                # Determine keep mode (validated by settings form, but be defensive).
                if keep_days is not None and keep_days >= 1 and keep_count is None:
                    keep_kwargs = {"keep_days": int(keep_days), "keep_count": None}
                elif keep_count is not None and keep_count >= 1 and keep_days is None:
                    keep_kwargs = {"keep_days": None, "keep_count": int(keep_count)}
                elif keep_days is not None and keep_days >= 1 and keep_count is not None and keep_count >= 1:
                    # Prefer days if both are set.
                    keep_kwargs = {"keep_days": int(keep_days), "keep_count": None}
                else:
                    keep_kwargs = None

                last_run_at = settings.get("last_run_at")
                should_run = last_run_at is None
                if last_run_at is not None:
                    try:
                        should_run = (datetime.now() - last_run_at).total_seconds() >= interval_seconds
                    except Exception:
                        should_run = True

                if keep_kwargs and should_run:
                    prune_backups(
                        scope_type=scope_type,
                        scope_instance_id=scope_instance_id,
                        keep_days=keep_kwargs["keep_days"],
                        keep_count=keep_kwargs["keep_count"],
                    )
                    db.set_backup_prune_last_run_at(datetime.now())
                    logger.info(
                        f"Auto prune ran. scope_type={scope_type}, "
                        f"scope_instance_id={scope_instance_id}"
                    )

                time.sleep(interval_seconds)
            else:
                time.sleep(3600)
        except Exception as e:
            logger.error(f"Auto prune loop error: {e}", exc_info=True)
            time.sleep(300)


@app.route('/api/backups/latest')
def api_latest_backups():
    """API endpoint to get the latest backup date and time for each instance."""
    latest_backups = db.get_latest_backup_per_instance()
    
    # Format the response
    result = []
    for item in latest_backups:
        result.append({
            'instance_id': item['instance_id'],
            'instance_name': item['instance_name'],
            'latest_backup': item['latest_backup'].isoformat() if item['latest_backup'] else None
        })
    
    return jsonify(result)


# Start background auto-prune worker.
threading.Thread(target=_auto_prune_loop, daemon=True).start()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

