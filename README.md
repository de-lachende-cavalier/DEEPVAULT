# DEEPVAULT

DEEPVAULT is a password manager meant to offer uncompromising security and privacy.
For further information, check the various specs in the `docs/` directory.

**N.B: The project is in its alpha/PoC stage!**

## Running the code

DEEPVAULT relies mainly on Django and NodeJS. It uses `Python 3.8`.
To run it locally, follow these steps:

1. Navigate to the project directory (`cd DEEPVAULT`);

2. Create a virtual environment and activate it (`python3.8 -m venv venv` and `source venv/bin/activate`);

3. Navigate to the `deepapi/` directory and run `npm install` to install the NodeJS dependencies;

4. Go back to the root directory (`cd ..`), and install all the python dependencies (`pip install -r requirements.txt`);

5. Start a local PostgreSQL server (`sudo service postgresql start`), have it listen on port 9863, and set the `DB_USER`, `DB_PASS` and `DB_NAME` environment variables to the appropriate values (the ones used for PostgreSQL);

6. Set the `DJ_KEY` environment variable (`export DJ_KEY=<your_key>`);

7. Run the `pre_setup` script (found in the `scripts/` directory) to take care of the initial node setup;

8. Initialise the database (`python manage.py migrate` and `python manage.py createsuperuser`);

8. Create a certificate/key pair for HTTPS (e.g., `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes`);

9. Collect the static files (`python manage.py collectstatic`);

10. Run gunicorn to start the Django server (`gunicorn DEEPVAULT.wsgi:application --bind 127.0.0.1:9000 --certfile cert.pem --keyfile key.pem`);

11. Open https://127.0.0.1:9000.
