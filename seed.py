"""
Create the database tables and the default administrator account.

    python seed.py
"""

from app import create_app
from extensions import db
from models import User
from config import Config


def main():
    app = create_app()
    with app.app_context():
        db.create_all()

        admin = User.query.filter_by(username=Config.ADMIN_USERNAME).first()
        if admin is None:
            admin = User(username=Config.ADMIN_USERNAME,
                         email=Config.ADMIN_EMAIL,
                         is_admin=True)
            admin.set_password(Config.ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()
            print("Admin account created: %s / %s"
                  % (Config.ADMIN_USERNAME, Config.ADMIN_PASSWORD))
        else:
            admin.is_admin = True
            db.session.commit()
            print("Admin account already exists:", admin.username)

        print("Users      :", User.query.count())
        print("Database   :", app.config["SQLALCHEMY_DATABASE_URI"])


if __name__ == "__main__":
    main()
