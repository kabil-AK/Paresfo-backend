import express from 'express';
import bcrypt from 'bcryptjs';
import {User} from '../models/User.js';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

const router = express.Router();



router.post('/signup', async (req, res) => {
    console.log("REQUEST BODY:", req.body);
  
    const { username, email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (user) {
      return res.json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    return res.json({status:true, message: 'User created successfully' });

  
});

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'User not found' });
    }
    const ValidPassword = await bcrypt.compare(password, user.password);
    if (!ValidPassword) {
        return res.json({ message: 'Invalid password' });
    }
    const token = jwt.sign({username:user.username},process.env.KEY,{expiresIn:'1h'});
    res.cookie('token',token,{httpOnly:true, maxAge:3600000});
    return res.json({status:true, message: 'Login successful' });
});

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({ message: 'User not found' });

        }
        const token = jwt.sign({id:user._id},process.env.KEY,{expiresIn:'5m'});

        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            }
});
  const resetLink = `${process.env.CLIENT_URL}/reset-Password/${token}`;
const mailOptions = {
  from: 'process.env.EMAIL_USER',
  to: email,
  subject: 'Reset Password',
  html: `
                <p>Click the link below to reset your password:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p>This link is valid for 5 minutes.</p>
            `
};

await transporter.sendMail(mailOptions);

        return res.json({ status: true, message: "Email sent successfully" });

    } catch (error) {
        console.log(error);
        return res.json({ message: "Error sending email" });
    }
});


router.post('/reset-password/:token', async(req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    try {
        const decoded =await jwt.verify(token, process.env.KEY);
        const id = decoded.id;
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate({_id:id}, { password: hashedPassword });
        return res.json({status:true, message: 'Updated Password' });
    } catch (error) {
        return res.json({ message: 'Invalid or expired token' });
    }
});


const verifyUser = async (req, res, next) => {
    try{
    const token = req.cookies.token;
    if (!token) {
        return res.json({ status: false, message: 'No token provided' });
    }
    jwt.verify(token, process.env.KEY);
    next();
    } catch (error) {
        return res.json({ status: false, message: 'Error retrieving token' });
    }
}
router.get('/verify',verifyUser, (req, res) => {
    return res.json({status:true,message:'Authorized' });
})


router.get('/logout', (req, res) => {
    res.clearCookie('token');
  return  res.json({status:true, message: 'Logged out successfully' });
});



export { router as UserRouter };