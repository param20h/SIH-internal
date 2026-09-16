# TVA Production Deployment Guide

This guide covers deploying the Threat Variance Authority (TVA) stack using a modern, scalable PaaS architecture:
- **Frontend:** Vercel
- **Backend API & Worker:** Render
- **Database (PostgreSQL):** Supabase
- **Message Broker (Redis):** Upstash

---

## Phase 1: Managed Infrastructure (Supabase & Upstash)

Before deploying the code, you need a database and a message broker for the backend to talk to.

### 1. Set up PostgreSQL on Supabase
1. Create a free account at [Supabase](https://supabase.com).
2. Create a new Project. Name it `tva-db`.
3. Once the database provisions, go to **Project Settings -> Database**.
4. Scroll down to **Connection String -> URI**.
5. Copy the connection string. It will look something like this:
   `postgresql://postgres.xxxxxx:[YOUR-PASSWORD]@aws-0-REGION.pooler.supabase.com:6543/postgres`
6. **Save this URI.** You will need it as `DATABASE_URL` in the next phase.

### 2. Set up Managed Redis on Upstash
1. Create a free account at [Upstash](https://upstash.com).
2. Create a new Redis Database.
3. Once provisioned, scroll down to the **Connect** section.
4. Select the **Redis URL** tab and copy the `rediss://...` link.
5. **Save this URI.** You will need it as `REDIS_URL` in the next phase.

---

## Phase 2: Deploying the Backend on Render

Render will host the Python FastAPI server and the Celery background worker. 

### 1. Deploy the API Web Service
1. Create a free account at [Render](https://render.com).
2. Click **New + -> Web Service** and connect your GitHub repository (`SIH-internal`).
3. Configure the Web Service:
   - **Name:** `tva-api`
   - **Root Directory:** `backend` *(Important!)*
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -e . && alembic upgrade head` *(This installs dependencies and runs database migrations)*
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Expand **Environment Variables** and add:
   - `DATABASE_URL` = [Your Supabase URI]
   - `REDIS_URL` = [Your Upstash URI]
   - `ENVIRONMENT` = `production`
5. Click **Create Web Service**.
6. Once deployed, Render will give you a live URL (e.g., `https://tva-api.onrender.com`). **Save this URL.**

### 2. Deploy the Celery Worker
1. In the Render Dashboard, click **New + -> Background Worker**.
2. Connect the same GitHub repository.
3. Configure the Worker:
   - **Name:** `tva-worker`
   - **Root Directory:** `backend`
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -e .`
   - **Start Command:** `celery -A app.core.celery_app.celery_app worker --loglevel=INFO`
4. Add the exact same **Environment Variables** (`DATABASE_URL`, `REDIS_URL`, `ENVIRONMENT`).
5. Click **Create Background Worker**.

### 3. Keep the API Awake (Uptime Bot)
Since Render's free tier sleeps after 15 minutes of inactivity, use a free uptime monitoring service like [UptimeRobot](https://uptimerobot.com).
1. Create a new monitor on UptimeRobot.
2. Monitor Type: **HTTP(s)**
3. URL: `https://tva-api.onrender.com/health` (or whatever the root URL is).
4. Interval: Every 5 minutes.
This will ping the API constantly, preventing cold starts when someone uses your frontend. *(Note: Render limits free tier hours, so it will eventually exhaust them if kept awake 24/7).*

---

## Phase 3: Deploying the Frontend on Vercel

Finally, deploy the React/Vite interface so users can access the application.

1. Create a free account at [Vercel](https://vercel.com) and connect your GitHub.
2. Click **Add New -> Project** and select your `SIH-internal` repository.
3. Configure the Project:
   - **Framework Preset:** Vite
   - **Root Directory:** `frontend` *(Important!)*
4. Expand **Environment Variables** and add:
   - `VITE_API_URL` = `https://tva-api.onrender.com` *(The live Render URL from Phase 2)*
5. Click **Deploy**.

Vercel will build the frontend, inject the `VITE_API_URL` into the static bundle, and give you a live `https://...vercel.app` URL.

---

## ⚠️ Important Production Notes
1. **MaxMind GeoIP Database:** The `backend/data/geoip/GeoLite2-City.mmdb` file is ignored by Git because it is massive. In production, geolocation will simply gracefully degrade to "No hop geolocation available". If you want it to work on Render, you'll need to download it in a custom build script (e.g., `curl -o data/geoip/GeoLite2-City.mmdb [YOUR-MAXMIND-LINK] && pip install -e .`).
2. **CORS:** Ensure your FastAPI backend allows cross-origin requests from your new Vercel domain. Check `backend/app/main.py` (or your config) to ensure `ALLOW_ORIGINS` includes your `vercel.app` domain.
