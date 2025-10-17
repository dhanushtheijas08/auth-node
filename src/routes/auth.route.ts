import { Router } from "express";
import {
  login,
  register,
  verifyUserEmail,
  resendOtp,
  logout,
  refreshToken,
} from "../controllers/auth.controller";

const route = Router();

route.post("/register", register);
route.post("/verify-email", verifyUserEmail);
route.post("/resend-otp", resendOtp);
route.post("/login", login);
route.post("/logout", logout);
route.post("/refresh-token", refreshToken);

export default route;
