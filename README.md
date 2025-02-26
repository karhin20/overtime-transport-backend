# Otoworker Calculator Backend

Backend service for managing worker overtime and transportation calculations.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file based on `.env.example` and fill in your values:
```bash
cp .env.example .env
```

3. Set up Supabase tables:

Create the following tables in your Supabase database:

### admins
- id (uuid, primary key)
- email (text, unique)
- password (text)
- created_at (timestamp with time zone)

### workers
- id (uuid, primary key)
- name (text)
- staffId (text, unique)
- grade (text)
- defaultArea (text)
- transportRequired (boolean)
- created_at (timestamp with time zone)

### overtime_entries
- id (uuid, primary key)
- workerId (uuid, foreign key to workers.id)
- date (date)
- entryTime (text)
- exitTime (text)
- transportation (boolean)
- category (text)
- created_at (timestamp with time zone)

## API Endpoints

### Admin Authentication

#### POST /api/admin/signup
Create a new admin account (requires secret code)
```json
{
  "email": "admin@example.com",
  "password": "password123",
  "secretCode": "your_secret_code"
}
```

#### POST /api/admin/signin
Sign in as an admin
```json
{
  "email": "admin@example.com",
  "password": "password123"
}
```

### Worker Management

#### POST /api/workers
Create a new worker (requires authentication)
```json
{
  "name": "John Doe",
  "staffId": "EMP123",
  "grade": "General Worker",
  "defaultArea": "Abeka Lapaz",
  "transportRequired": true
}
```

#### GET /api/workers
Get all workers (requires authentication)

### Overtime Management

#### POST /api/overtime
Add overtime entry (requires authentication)
```json
{
  "workerId": "worker_uuid",
  "date": "2024-01-15",
  "entryTime": "17:00",
  "exitTime": "20:00",
  "transportation": true,
  "category": "A"
}
```

#### GET /api/overtime/:workerId
Get overtime entries for a worker (requires authentication)
Query parameters:
- startDate (optional)
- endDate (optional)

#### GET /api/summary/monthly
Get monthly summary (requires authentication)
Query parameters:
- month (1-12)
- year (YYYY)

## Development

Run the development server:
```bash
npm run dev
```

## Production

Start the production server:
```bash
npm start
```

## Deployment on Vercel

1. Create a new project on Vercel
2. Link your repository
3. Set up environment variables in Vercel dashboard
4. Deploy!
