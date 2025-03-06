# QRuSafe-Project

Summary of What to Install
To run this project locally or deploy it elsewhere, ensure the following dependencies are installed.

1. Install Backend Dependencies
Run this inside the backend folder:
npm install express axios cors dotenv node-fetch

2. Install Frontend Dependencies
Inside the frontend folder:
npm install html5-qrcode axios


3. Make Sure .env is Set Up
Create .env in the backend folder:
GOOGLE_API_KEY=your_google_api_key
VIRUS_TOTAL_API_KEY=your_virustotal_api_key
PORT=5000



4. Start the Project
Run backend:
cd backend
node server.js
--------------------------
Run frontend:
cd frontend
npm start