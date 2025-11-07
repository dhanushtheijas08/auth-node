import { Router } from "express";
import {
  forgotPassword,
  login,
  logout,
  refreshToken,
  register,
  resendVerificationCode,
  resetPassword,
  verifyUserEmail,
} from "../controllers/auth.controller";
import {
  loginRateLimitMiddleware,
  refreshTokenRateLimitMiddleware,
  registerRateLimitMiddleware,
  resendOtpRateLimitMiddleware,
  verifyEmailRateLimitMiddleware,
  forgotPasswordRateLimitMiddleware,
} from "../middleware/rateLimiter";
import { validator } from "../middleware/validater";
import {
  forgortPasswordSchme,
  resetPasswordSchme,
} from "../schemas/auth.schema";
const authRouter = Router();

authRouter.post("/register", registerRateLimitMiddleware, register);
authRouter.post(
  "/verify-email",
  verifyEmailRateLimitMiddleware,
  verifyUserEmail
);
authRouter.post(
  "/resend-verification-code",
  resendOtpRateLimitMiddleware,
  resendVerificationCode
);
authRouter.post("/login", loginRateLimitMiddleware, login);

authRouter.post(
  "/forgot-password",
  forgotPasswordRateLimitMiddleware,
  validator({ body: forgortPasswordSchme }),
  forgotPassword
);

authRouter.post(
  "/reset-password",
  validator({ body: resetPasswordSchme }),
  resetPassword
);

authRouter.delete("/logout", logout);
authRouter.post(
  "/refresh-token",
  refreshTokenRateLimitMiddleware,
  refreshToken
);

export default authRouter;
