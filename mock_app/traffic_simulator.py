"""
Simule du trafic utilisateur normal sur la plateforme Vinted Algeria.
Lance ce script pendant que tu fais des attaques depuis Kali pour
créer un mélange réaliste de trafic légitime et malveillant.
"""
import requests
import time
import random
from faker import Faker

fake = Faker('fr_FR')
BASE = "http://localhost:5000"
USERS = [
    ("amel@gmail.com", "pass123"),
    ("yacine@gmail.com", "pass456"),
]

def normal_browse():
    """Un utilisateur qui parcourt les annonces."""
    s = requests.Session()
    s.get(f"{BASE}/api/listings")
    time.sleep(random.uniform(2, 8))
    listing_id = random.randint(1, 8)
    s.get(f"{BASE}/api/listings/{listing_id}")
    time.sleep(random.uniform(1, 5))

def normal_login():
    """Un utilisateur qui se connecte."""
    email, pwd = random.choice(USERS)
    requests.post(f"{BASE}/api/auth/login",
                  json={"email": email, "password": pwd})
    time.sleep(random.uniform(1, 3))

def failed_login():
    """Un utilisateur qui se trompe de mot de passe — normal."""
    email, _ = random.choice(USERS)
    requests.post(f"{BASE}/api/auth/login",
                  json={"email": email, "password": "wrongpass"})

def normal_message():
    requests.post(f"{BASE}/api/messages",
                  json={"to": 2, "content": fake.sentence()})

actions = [
    (normal_browse, 50),   # 50% du temps = navigation
    (normal_login, 25),    # 25% = connexion
    (failed_login, 10),    # 10% = mauvais mdp (normal)
    (normal_message, 15),  # 15% = messages
]

def weighted_choice(actions):
    total = sum(w for _, w in actions)
    r = random.uniform(0, total)
    upto = 0
    for action, weight in actions:
        if upto + weight >= r:
            return action
        upto += weight

print("Simulateur de trafic normal démarré. Ctrl+C pour arrêter.")
print(f"Logs dans : data/generated_logs/access.log")

while True:
    try:
        action = weighted_choice(actions)
        action()
        time.sleep(random.uniform(0.5, 3))
    except requests.exceptions.ConnectionError:
        print("Flask app non disponible. Attente...")
        time.sleep(5)
    except KeyboardInterrupt:
        print("Simulateur arrêté.")
        break