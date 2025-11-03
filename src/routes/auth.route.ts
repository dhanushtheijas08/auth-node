import { Router } from "express";
import {
  login,
  register,
  verifyUserEmail,
  resendOtp,
  logout,
  refreshToken,
} from "../controllers/auth.controller";
import {
  loginRateLimitMiddleware,
  registerRateLimitMiddleware,
  verifyEmailRateLimitMiddleware,
  resendOtpRateLimitMiddleware,
  refreshTokenRateLimitMiddleware,
} from "../middleware/rateLimiter";
const route = Router();

route.post("/register", registerRateLimitMiddleware, register);
route.post("/verify-email", verifyEmailRateLimitMiddleware, verifyUserEmail);
route.post("/resend-otp", resendOtpRateLimitMiddleware, resendOtp);
route.post("/login", loginRateLimitMiddleware, login);
route.delete("/logout", logout);
route.post("/refresh-token", refreshTokenRateLimitMiddleware, refreshToken);

export default route;
