import { Verification_Type as VerificationType } from "@prisma/client";
import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import z from "zod";
import { prisma } from "../config/db";
import { sendMail } from "../lib/mail";
import {
  forgortPasswordSchme,
  loginSchema,
  registerSchema,
  resendOtpSchema,
  resetPasswordSchme,
  verifyEmailBodySchema,
  verifyEmailQuerySchema,
} from "../schemas/auth.schema";
import {
  clearTokenCookies,
  setAccessTokenCookie,
  setTokenCookies,
} from "../services/cookie.service";
import {
  generateAccessToken,
  generateTokenPair,
  verifyToken,
} from "../services/jwt.service";
import { createSession } from "../services/session.service";
import { verificationCode } from "../services/verification.service";
import { ApiError } from "../utils/ApiError";
import { verificationCodeGenerator } from "../utils/verificationCodeGenerator";
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
    await sendMail("VERIFY_EMAIL", code, user.email);

    const encodedEmail = encodeURIComponent(user.email);
    const encodedType = encodeURIComponent("VERIFY_EMAIL");
    res.status(201).json({
      status: "ok",
      message: "Verify your email",
      redirectRoute: `/verify-email?email=${encodedEmail}&verificationType=${encodedType}`,
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
    const { email, verificationType: type } = verifyEmailQuerySchema.parse(
      req.query
    );
    const { code } = verifyEmailBodySchema.parse(req.body);
    const user = await prisma.user.findUnique({ where: { email: email } });
    if (!user)
      throw new ApiError(
        "Invalid verification code or email",
        400,
        "/register"
      );
    else if (user && user.isVerified)
      throw new ApiError("User already verified", 400, "/login");

    const verificationRecord = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: type as VerificationType,
        code: code,
        expiresAt: { gt: new Date() },
      },
    });

    if (!verificationRecord) {
      throw new ApiError("Invalid verification code or email", 400);
    }

    await prisma.verificationCode.delete({
      where: { id: verificationRecord.id },
    });

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
      redirectRoute: "/dashboard",
    });
  } catch (error) {
    next(error);
  }
};

export const resendVerificationCode = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, verificationType } = resendOtpSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user)
      throw new ApiError("Invalid email or user not found", 400, "/register");
    if (user.isVerified)
      throw new ApiError("User already verified", 400, "/login");

    const verificationRecord = await verificationCode(
      user.id,
      verificationType
    );

    const timeSinceCreation =
      Date.now() - verificationRecord.createdAt.getTime();
    const resendWaitMs = 2 * 60 * 1000; // 2 minutes in ms

    if (timeSinceCreation < resendWaitMs) {
      const remainingSeconds = Math.ceil(
        (resendWaitMs - timeSinceCreation) / 1000
      );
      throw new ApiError(
        `Please wait ${remainingSeconds} seconds before requesting a new OTP.`,
        429
      );
    }

    const newCode = verificationCodeGenerator(verificationType);

    await prisma.verificationCode.update({
      where: { id: verificationRecord.id },
      data: {
        code: newCode,
        expiresAt: new Date(Date.now() + 1000 * 60 * 5),
        createdAt: new Date(),
      },
    });

    await sendMail(verificationType, newCode, user.email);

    return res.status(200).json({
      status: "ok",
      message: "New verification code sent to your email.",
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

    const user = await prisma.user.findUnique({
      where: { email },
    });
    if (!user)
      throw new ApiError("Invalid email or password", 401, "/register");

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect)
      throw new ApiError("Invalid email or password", 401);

    if (!user.isVerified) {
      const { code, isNewCode } = await verificationCode(
        user.id,
        "VERIFY_EMAIL"
      );

      if (isNewCode) {
        await sendMail("VERIFY_EMAIL", code, user.email);
      }

      const encodedEmail = encodeURIComponent(user.email);
      const encodedType = encodeURIComponent("VERIFY_EMAIL");
      return res.status(200).json({
        status: "ok",
        message: "Verification email sent to your inbox.",
        redirectRoute: `/verify-email?email=${encodedEmail}&verificationType=${encodedType}`,
      });
    }

    // If verified, create session and tokens
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
      message: "Login successful",
    });
  } catch (error) {
    next(error);
  }
};

export const forgotPassword = async (
  req: Request<{}, {}, z.infer<typeof forgortPasswordSchme>>,
  res: Response,
  next: NextFunction
) => {
  const { email, verificationType } = req.body;
  if (verificationType !== "RESET_PASSWORD")
    throw new ApiError("Invalid verification type", 401);

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.isVerified)
      throw new ApiError("Not Verified User", 401, "/login");

    const recentGeneratedCode = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: verificationType,
        createdAt: { gte: new Date(Date.now() - 3 * 60 * 1000) },
      },
    });

    if (recentGeneratedCode) {
      const now = Date.now();
      const created = new Date(recentGeneratedCode.createdAt).getTime();

      const diffMs = now - created; // how long ago it was created
      const cooldownMs = 3 * 60 * 1000; // 3 minutes in ms
      const remainingMs = cooldownMs - diffMs;

      const remainingSeconds = Math.ceil(remainingMs / 1000);
      const remainingMinutes = Math.floor(remainingSeconds / 60);
      const seconds = remainingSeconds % 60;

      throw new ApiError(
        `Please wait ${remainingMinutes}m ${seconds}s before requesting a new code.`,
        429
      );
    }

    const code = verificationCodeGenerator("RESET_PASSWORD");

    const verificationCode = await prisma.verificationCode.create({
      data: {
        code,
        expiresAt: new Date(Date.now() + 1000 * 60 * 5),
        type: verificationType,
        userId: user.id,
      },
    });

    await sendMail(verificationType, verificationCode.code, user.email);
    return res.status(200).json({
      status: "ok",
      message: "Reset password code sent to your email.",
      redirectRoute: `/reset-password?email=${email}`,
    });
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (
  req: Request<{}, {}, z.infer<typeof resetPasswordSchme>>,
  res: Response,
  next: NextFunction
) => {
  const { email, password, code } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw new ApiError("Not Verified User", 400, "/login");

    const verificationCode = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: "RESET_PASSWORD",
        expiresAt: { lt: new Date(Date.now()) },
      },
    });
    if (!verificationCode || verificationCode.code !== code)
      throw new ApiError("Invalid verification code", 400);

    await prisma.user.update({
      where: { id: user.id },
      data: { password: await bcrypt.hash(password, 10) },
    });
    return res.status(200).json({
      status: "ok",
      message: "Password reset successful",
      redirectRoute: "/login",
    });
  } catch (error) {
    next(error);
  }
};

export const logout = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { accessToken } = req.cookies;
    if (!accessToken) throw new ApiError("Unauthorized", 401);

    const { jti: sessionId } = await verifyToken(accessToken);

    const session = await prisma.session.findUnique({
      where: { id: sessionId },
    });
    if (!session) throw new ApiError("Unauthorized", 401);
    if (session.expiresAt < new Date())
      throw new ApiError("Session expired", 401);

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });
    if (!user) throw new ApiError("Unauthorized", 401);

    await prisma.session.delete({ where: { id: session.id } });
    clearTokenCookies(res);
    return res.status(200).json({
      status: "ok",
      message: "Logout successful",
      redirectRoute: "/login",
    });
  } catch (error) {
    next(error);
  }
};

export const refreshToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { refreshToken: oldRefreshToken } = req.cookies;
    if (!oldRefreshToken) throw new ApiError("Unauthorized", 401);

    const { jti: sessionId } = await verifyToken(oldRefreshToken);

    const session = await prisma.session.findUnique({
      where: { id: sessionId },
    });
    if (!session) throw new ApiError("Unauthorized", 401);
    if (session.expiresAt < new Date())
      throw new ApiError("Session expired", 401);

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });
    if (!user) throw new ApiError("Unauthorized", 401);

    if (session.expiresAt < new Date(Date.now() + 1000 * 60 * 60 * 24)) {
      await prisma.session.delete({ where: { id: session.id } });
      const newSession = await createSession(user.id, req);
      const { accessToken, refreshToken } = await generateTokenPair(
        {
          userId: user.id,
          role: user.role,
        },
        newSession.id
      );
      setTokenCookies(res, accessToken, refreshToken);
    } else {
      const accessToken = await generateAccessToken(
        {
          userId: user.id,
          role: user.role,
        },
        session.id
      );

      setAccessTokenCookie(res, accessToken);
    }

    return res.status(200).json({
      status: "ok",
      message: "Token refreshed",
    });
  } catch (error) {
    next(error);
  }
};
