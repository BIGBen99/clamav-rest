# --- Étape 1 : image de base Python ---
FROM python:3.12-slim

# --- Variables d'environnement ---
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# --- Définir le répertoire de travail ---
WORKDIR /app

# --- Copier les fichiers requirements et .env ---
COPY requirements.txt .

# --- Installer les dépendances ---
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# --- Copier le reste du code ---
COPY . .

# --- Exposer le port sur lequel FastAPI tourne ---
EXPOSE 9000

# --- Commande pour lancer l'application ---
CMD ["uvicorn", "clamav_rest:app", "--host", "0.0.0.0", "--port", "9000"]
