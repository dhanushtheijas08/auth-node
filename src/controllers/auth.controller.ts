import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import { prisma } from "../config/db";
import { sendMail } from "../lib/mail";
import { loginSchema, registerSchema } from "../schemas/auth.schema";
import { verificationCode } from "../services/verification.service";
import { ApiError } from "../utils/ApiError";
import { generateTokenPair } from "../services/jwt.service";
import { setTokenCookies } from "../services/cookie.service";
import { createSession } from "../services/session.service";

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
      code: code,
    });
  } catch (error) {
    next(error);
  }
};

export const verifyUserEmail = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, type } = req.params;
    const { code } = req.body;

    const user = await prisma.user.findUnique({ where: { email: email } });
    if (!user) throw new ApiError("Invalide User", 500, "/register");
    else if (user && user.isVerified)
      throw new ApiError("Verified user", 400, "/login");

    const verificationCode = await prisma.verificationCode.findUnique({
      where: { code_userId: { code: code, userId: user.id } },
    });

    if (!verificationCode || verificationCode.expiresAt < new Date()) {
      throw new ApiError("Invalid code", 500);
    }

    if (code !== verificationCode.code) {
      throw new ApiError("Not correct");
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true },
    });

    const session = await createSession(user.id, req);

    const { accessToken, refreshToken } = await generateTokenPair(
      {
        userId: user.id,
        role: user.role,
      },
      session.id
    );

    setTokenCookies(res, accessToken, refreshToken);

    return res.status(200).json({
      status: "ok",
      message: "User verified",
    });
  } catch (error) {
    next(error);
  }
};

export const login = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const isValidUser = await prisma.user.findUnique({
      where: { email },
    });

    if (!isValidUser) throw new ApiError("Not valid user", 500, "/register");
    if (!isValidUser.isVerified)
      throw new ApiError("Verify you email", 500, "/register");

    const isValidPassword = await bcrypt.compare(
      password,
      isValidUser.password
    );
    if (!isValidPassword) throw new ApiError("Not valid user", 500);

    const session = await createSession(isValidUser.id, req);

    const { accessToken, refreshToken } = await generateTokenPair(
      {
        userId: isValidUser.id,
        role: isValidUser.role,
      },
      session.id
    );

    setTokenCookies(res, accessToken, refreshToken);

    return res.status(200).json({
      status: "ok",
      message: "Login successful",
    });
  } catch (error) {
    next(error);
  }
};
