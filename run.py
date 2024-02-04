# my_simple_flask_app/run.py
from app import app, db


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True, host='0.0.0.0')
