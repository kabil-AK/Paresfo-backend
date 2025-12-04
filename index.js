import express from 'express';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { UserRouter } from './routes/user.js';

dotenv.config();

const app = express();

app.use(express.json());



app.use(cors({
    origin: [
    "http://localhost:5173",          // local frontend
    "http://localhost:5174",          // vite sometimes runs here
    "https://paresfooo.netlify.app"   // your Netlify URL
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

app.use(cookieParser());

app.use('/auth', UserRouter);  

mongoose.connect('mongodb://127.0.0.1:27017/authenticationDB')
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('Could not connect to MongoDB...', err));

app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});