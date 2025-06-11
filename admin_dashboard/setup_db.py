from server import app, db
from flask_login import UserMixin

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='admin')

def setup_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            admin = Admin(
                username='admin',
                password='admin',  # In production, use proper password hashing
                email='admin@agis.com',
                role='superadmin'
            )
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created successfully')
        else:
            print('Admin user already exists')

if __name__ == '__main__':
    setup_database() 