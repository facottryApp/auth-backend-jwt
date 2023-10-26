import { registerUser, loginUser, sendOTP, verifyOTP, isRegistered } from "./controllers/auth.js";
import { Router } from "express";
const router = Router();

//AUTH
router.post("/login", loginUser);
router.post("/is-registered", isRegistered);
router.post("/send-otp", sendOTP);
router.post("/verify-otp", verifyOTP);
router.post("/register", registerUser);

export default router;