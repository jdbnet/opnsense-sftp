"""
Flask application for OPNsense backup management via SFTP.
"""
import os
from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify, flash
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from database import Database
from ssh_keys import SSHKeyManager
from sftp_server import SFTPThreadedServer
from logger_config import setup_logging, get_logger

# Load environment variables
load_dotenv()

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Read version from VERSION file or environment
def get_version():
    """Get application version from VERSION file or environment variable."""
    # Check environment variable first (set during Docker build)
    env_version = os.getenv('APP_VERSION')
    if env_version and env_version != 'dev':
        return env_version
    
    # Fall back to VERSION file
    try:
        version_path = Path(__file__).parent / 'VERSION'
        if version_path.exists():
            return version_path.read_text().strip()
    except Exception:
        pass
    return 'dev'

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
        db.create_user('admin', generate_password_hash(default_password))
        logger.warning("Created default admin user (password: 'admin' - CHANGE THIS!)")
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


@app.route('/')
def index():
    """Redirect to dashboard if logged in, otherwise to login."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = db.get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard."""
    instances = db.get_all_instances()
    all_backups = db.get_all_backups()
    
    # Add instance info to each backup
    for backup in all_backups:
        instance = db.get_instance_by_id(backup['instance_id'])
        if instance:
            backup['instance_name'] = instance['name']
            backup['instance_identifier'] = instance['identifier']
    
    return render_template('dashboard.html', instances=instances, backups=all_backups, sftp_server=sftp_server)


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
    """List all backups."""
    all_backups = db.get_all_backups()
    
    # Add instance info to each backup
    for backup in all_backups:
        instance = db.get_instance_by_id(backup['instance_id'])
        if instance:
            backup['instance_name'] = instance['name']
            backup['instance_identifier'] = instance['identifier']
    
    return render_template('backups.html', backups=all_backups)


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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

