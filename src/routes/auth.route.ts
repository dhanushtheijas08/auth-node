import { Router } from "express";
import {
  login,
  register,
  verifyUserEmail,
} from "../controllers/auth.controller";

const route = Router();

route.post("/register", register);
route.post("/verify-email", verifyUserEmail);
route.post("/login", login);

export default route;
