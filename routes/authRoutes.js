import express from "express";
import { login, logOut, registerRequest,verifyOtpAndRegister,resendOtp  } from "../controllers/authController.js";

const authRoutes = express.Router();

authRoutes.post('/register', registerRequest)
authRoutes.post('/verify-otp', verifyOtpAndRegister);
authRoutes.post('/resend-otp', resendOtp);
authRoutes.post('/login', login)
authRoutes.post('/logout', logOut)

export default authRoutes;