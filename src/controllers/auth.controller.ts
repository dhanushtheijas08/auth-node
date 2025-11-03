import { Verification_Type as VerificationType } from "@prisma/client";
import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import { prisma } from "../config/db";
import { sendMail } from "../lib/mail";
import {
  loginSchema,
  registerSchema,
  resendOtpSchema,
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
    if (!user) throw new ApiError("Invalid User", 400, "/register");
    else if (user && user.isVerified)
      throw new ApiError("Verified user", 400, "/login");

    const verificationCode = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: type as VerificationType,
        code: code,
        expiresAt: { gt: new Date() },
      },
    });

    if (!verificationCode || verificationCode.expiresAt < new Date()) {
      throw new ApiError("Invalid or expired code", 400);
    }

    await prisma.verificationCode.delete({
      where: { id: verificationCode.id },
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

export const resendOtp = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, verificationType } = resendOtpSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw new ApiError("Invalid user", 400, "/register");
    if (user.isVerified)
      throw new ApiError("User already verified", 400, "/login");

    const { createdAt, id } = await verificationCode(user.id, verificationType);

    const timeSinceCreation = Date.now() - createdAt.getTime();
    const resendWait = 2 * 60 * 1000; // 2 minutes in ms

    if (timeSinceCreation < resendWait) {
      const remainingSeconds = Math.ceil(
        (resendWait - timeSinceCreation) / 1000
      );
      throw new ApiError(
        `Please wait ${remainingSeconds} seconds before requesting a new OTP.`,
        429
      );
    }

    const newCode = verificationCodeGenerator(verificationType);

    await prisma.verificationCode.delete({
      where: { id },
    });

    await prisma.verificationCode.create({
      data: {
        userId: user.id,
        type: verificationType,
        code: newCode,
        expiresAt: new Date(Date.now() + 1000 * 60 * 5),
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

    const isValidUser = await prisma.user.findUnique({
      where: { email },
    });
    if (!isValidUser) throw new ApiError("Invalid user", 401, "/register");

    const isValidPassword = await bcrypt.compare(
      password,
      isValidUser.password
    );
    if (!isValidPassword) throw new ApiError("Invalid credentials", 401);

    if (!isValidUser.isVerified) {
      const { code, isNewCode } = await verificationCode(
        isValidUser.id,
        "VERIFY_EMAIL"
      );

      if (isNewCode) {
        await sendMail("VERIFY_EMAIL", code, isValidUser.email);
        const encEmail = encodeURIComponent(isValidUser.email);
        const encType = encodeURIComponent("VERIFY_EMAIL");
        return res.status(200).json({
          status: "ok",
          message: "Verification email sent to your inbox.",
          redirectRoute: `/verify-email?email=${encEmail}&verificationType=${encType}`,
        });
      }

      const encEmail2 = encodeURIComponent(isValidUser.email);
      const encType2 = encodeURIComponent("VERIFY_EMAIL");
      return res.status(200).json({
        status: "ok",
        message:
          "Verification code was already sent to your email. Please check your inbox.",
        redirectRoute: `/verify-email?email=${encEmail2}&verificationType=${encType2}`,
      });
    }

    // If verified, create session and tokens
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
