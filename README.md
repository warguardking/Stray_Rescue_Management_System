# SRMS - Stray Rescue Management System

Web platform with two account types (registered user, registered shelter) and five modules: Reporting, Adoption, Fostering, Volunteering, Donation.
Three tiers: HTML/CSS/JavaScript frontend (static/index.html), Python application layer (server.py), SQLite database (srms.db).

## Run
1. Install Python 3.8 or newer (`python --version`; on Mac/Linux use `python3`).
2. Open a terminal inside this folder (the one containing server.py).
3. `python server.py`
4. Open http://localhost:8000. Stop with Ctrl+C.

## First test
1. Register a **Registered shelter** account. A verification code appears on screen (no email server is connected; it is also printed in the terminal). Verify, then log in.
2. As shelter: Adoptions > add an animal; Volunteer events > create an event.
3. Log out. Register a **Registered user**, verify, log in. Report a stray, apply to adopt, register for the event, submit a donation.
4. Log back in as the shelter and update the statuses. The user sees the status and note on their next visit.

Delete srms.db to reset all data.
