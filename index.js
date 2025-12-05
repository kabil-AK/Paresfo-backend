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
    "http://localhost:5173",       
    "http://localhost:5174",         
    "https://paresfooo.netlify.app"   
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

app.use(cookieParser());

app.use('/auth', UserRouter);  

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("Connected to MongoDB Atlas"))
  .catch(err => console.error("MongoDB connection error:", err));


app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});