import userModel from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import transporter from "../config/nodemailer.js";

export const registerRequest = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({ success: false, message: 'missing details' })
    }
    // Validating email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.json({ success: false, message: 'Invalid email format' });
    }
    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser && existingUser.isAccountVerifid) {
            return res.json({ success: false, message: 'User already exists' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;
        const hashedPassword = await bcrypt.hash(password, 10);
        let userToVerify;
        if (existingUser) {
            // Updating the existing, unverified user record
            existingUser.name = name;
            existingUser.password = hashedPassword;
            existingUser.verifyOtp = otp;
            existingUser.verifyOtpExpAt = otpExpiry;
            userToVerify = await existingUser.save();
        } else {
            // Creating a new unverified user
            userToVerify = await userModel.create({
                name,
                email,
                password: hashedPassword,
                verifyOtp: otp,
                verifyOtpExpAt: otpExpiry,
                isAccountVerifid: false
            });
        }
        // temporary verification token
        const verificationToken = jwt.sign(
            { id: userToVerify._id },
            process.env.JWT_SECRET,
            { expiresIn: '60m' }
        );
        // temporary verification cookie
        res.cookie('verificationToken', verificationToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 60 * 60 * 1000,
        });

       //  otp mail
        const mailContent = {
            from: process.env.SENDER_MAIL,
            to: email,
            subject: 'Email Verification OTP',
            text: `Your OTP for registration is: ${otp}. It expires in 10 minutes.`,
        };
        await transporter.sendMail(mailContent)

        return res.json({ success: true, message: 'OTP sent to your email. Please verify.' });

    } catch (err) {
        res.json({ success: false, message: err.message })
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "email and password are required" })
    }
    try {
        // finding the user and validating
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Invalid Email" })
        }
        const isPasswordMatch = await bcrypt.compare(password, user.password)
        if (!isPasswordMatch) {
            return res.json({ success: false, message: "Invalid Password" })
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' })
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000,

        })
        return res.json({ success: true });

    } catch (err) {
        res.json({ success: false, message: err.message })
    }
}

export const logOut = async (req, res) => {
    try {
        // clearing the cookie when we logout
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
        })
        return res.json({ success: true, message: "Logged Out" })
    } catch (err) {
        return res.json({ success: false, message: err.message })
    }
}

export const verifyOtpAndRegister = async (req, res) => {
    const { otp } = req.body;
    const { verificationToken } = req.cookies;

    if (!otp || !verificationToken) {
        return res.json({ success: false, message: "OTP and verification token are required." });
    }
    try {
        // Verify the JWT to get the user's ID
        const decoded = jwt.verify(verificationToken, process.env.JWT_SECRET);
        // Finding the user by the ID from the token
        const user = await userModel.findById(decoded.id);

        if (!user) {
            return res.json({ success: false, message: "Verification failed. Please try registering again." });
        }
        if (user.isAccountVerifid) {
            return res.json({ success: false, message: "Account already verified. Please login." });
        }
        if (Date.now() > user.verifyOtpExpAt) {
            return res.json({ success: false, message: "OTP expired. Please request a new one." });
        }
        if (otp !== user.verifyOtp) {
            return res.json({ success: false, message: "Invalid OTP." });
        }

        // OTP valid
        user.verifyOtp = "";
        user.verifyOtpExpAt = 0;
        user.isAccountVerifid = true;
        await user.save();

        res.clearCookie('verificationToken'); // clearing the previously saved cookie in registerRequest controller
        // new token
        const loginToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        // new cookie 
        res.cookie('token', loginToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === "production" ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, 
        });
        return res.json({ success: true, message: "Account verified and created successfully. You are now logged in." });
    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            return res.json({ success: false, message: "Invalid or expired verification session. Please register again." });
        }
        return res.json({ success: false, message: err.message });
    }
}

export const resendOtp = async (req, res) => {
    const { verificationToken } = req.cookies;

    if (!verificationToken) {
        return res.status(401).json({ success: false, message: "Verification session not found. Please register again." });
    }

    try {
        const decoded = jwt.verify(verificationToken, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        if (user.isAccountVerifid) {
            return res.status(400).json({ success: false, message: "This account is already verified." });
        }

        // Check for cooldown after send otp
        const cooldown = 60 * 1000;
        const timeSinceLastResend = Date.now() - user.lastOtpResendAt;

        if (timeSinceLastResend < cooldown) {
            const timeLeft = Math.ceil((cooldown - timeSinceLastResend) / 1000);
            return res.status(429).json({ 
                success: false, 
                message: `Please wait ${timeLeft} more seconds before resending.` 
            });
        }

        // Generating a new OTP and expiry
        const newOtp = Math.floor(100000 + Math.random() * 900000).toString();
        const newOtpExpiry = Date.now() + 10 * 60 * 1000;

        // Updating the user document in the database
        user.verifyOtp = newOtp;
        user.verifyOtpExpAt = newOtpExpiry;
        user.lastOtpResendAt = Date.now();
        await user.save();

        // Sending the new OTP via email
        const mailContent = {
            from: process.env.SENDER_MAIL,
            to: user.email,
            subject: 'Your New Email Verification OTP',
            text: `Your new OTP for registration is: ${newOtp}. It expires in 10 minutes.`,
        };
        await transporter.sendMail(mailContent);

        return res.json({ success: true, message: "A new OTP has been sent to your email." });

    } catch (err) {
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ success: false, message: "Invalid or expired verification session." });
        }
        return res.status(500).json({ success: false, message: err.message });
    }
};