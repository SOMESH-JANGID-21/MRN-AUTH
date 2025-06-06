import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    verifyOtp: { type: String, default: '' },
    verifyOtpExpAt: { type: Number, default: 0 },
    verifyOtpExpAt: { type: Number, default: 0 },
    isAccountVerifid: { type: Boolean, default: false },
    resetOtp: { type: String, default: '' },
    resetOtpExpAt: { type: Number, default: 0 },
    lastOtpResendAt: {
        type: Number,
        default: 0
    }
})

const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;