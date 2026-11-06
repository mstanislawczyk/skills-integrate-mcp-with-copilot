# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Teachers can sign students up for activities and remove registrations
- Students can view activities and registered participants without signing in

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   uvicorn src.app:app --reload
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

4. Configure teacher access before signing in:

   ```
   python src/manage_teachers.py
   ```

   The command prompts for a teacher username and password and stores only a
   salted password hash in the local, git-ignored `src/teachers.json` file.
   Passwords must be at least 12 characters.

   Generate a session signing key and configure it in the server environment:

   ```
   export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
   ```

   Restart the server after setting the key. Use HTTPS in deployment; the
   teacher session cookie is Secure, HttpOnly, SameSite=Strict, and expires
   after eight hours.

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| GET    | `/auth/me`                                                        | Check whether a teacher is signed in                                |
| POST   | `/auth/login`                                                     | Sign in as a teacher                                                |
| POST   | `/auth/logout`                                                    | Sign out                                                           |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | (Teacher only) Sign up a student                                    |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | (Teacher only) Remove a registration                              |

Teacher credentials are provisioned locally and are not committed. The JSON
file stores PBKDF2-HMAC-SHA256 password hashes, salts, and iteration counts;
`SESSION_SECRET` must be a randomly generated value of at least 32 characters.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
