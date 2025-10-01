import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import { prisma } from "../config/db";
import { sendMail } from "../lib/mail";
import { registerSchema } from "../schemas/auth.schema";
import { verificationCode } from "../services/verification.service";
import { ApiError } from "../utils/ApiError";

export const register = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { name, email, password } = registerSchema.parse(req.body);
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) throw new ApiError("User already exists", 400, "/login");

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { email: email, name: name, password: hashedPassword },
    });

    const { code } = await verificationCode(user.id, "VERIFY_EMAIL");
    await sendMail("VERIFY_EMAIL", code);

    res.status(201).json({
      status: "ok",
      message: "Verify your email",
      redirectRoute: `/verify-code?email=${user.email}`,
    });
  } catch (error) {
    next(error);
  }
};
