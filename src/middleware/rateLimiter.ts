import {
  RateLimiterRedis,
  IRateLimiterRes,
  IRateLimiterOptions,
} from "rate-limiter-flexible";
import { Request, Response, NextFunction } from "express";
import redis from "../config/redis";
import { ApiError } from "../utils/ApiError";

type RateLimiterConfig = IRateLimiterOptions & { message: string };

const createRateLimitMiddleware = (config: RateLimiterConfig) => {
  const limiter = new RateLimiterRedis({
    storeClient: redis,
    keyPrefix: config.keyPrefix,
    points: config.points,
    duration: config.duration,
    blockDuration: config.blockDuration,
  });

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await limiter.consume(req.ip || "0.0.0.0");
      next();
    } catch (error: any) {
      const rejRes = error as IRateLimiterRes;
      const secs = Math.round((rejRes?.msBeforeNext ?? 0) / 1000) || 1;
      next(
        new ApiError(
          `${config.message} Please try again in ${secs} seconds.`,
          429
        )
      );
    }
  };
};

const rateLimiterConfigs = {
  login: {
    keyPrefix: "login",
    points: 5,
    duration: 60,
    blockDuration: 15 * 60,
    message: "Too many login attempts.",
  },
  register: {
    keyPrefix: "register",
    points: 3,
    duration: 3600,
    blockDuration: 30 * 60,
    message: "Too many registration attempts.",
  },
  verifyEmail: {
    keyPrefix: "verify-email",
    points: 5,
    duration: 600,
    blockDuration: 15 * 60,
    message: "Too many verification attempts.",
  },
  resendOtp: {
    keyPrefix: "resend-otp",
    points: 5,
    duration: 5 * 60,
    blockDuration: 10 * 60,
    message: "Too many OTP requests.",
  },
  forgotPassword: {
    keyPrefix: "forgot-password",
    points: 5,
    duration: 5 * 60,
    blockDuration: 10 * 60,
    message: "Too many password reset requests.",
  },
  refreshToken: {
    keyPrefix: "refresh-token",
    points: 10,
    duration: 60,
    blockDuration: 5 * 60,
    message: "Too many token refresh attempts.",
  },
};

export const loginRateLimitMiddleware = createRateLimitMiddleware(
  rateLimiterConfigs.login
);
export const registerRateLimitMiddleware = createRateLimitMiddleware(
  rateLimiterConfigs.register
);
export const verifyEmailRateLimitMiddleware = createRateLimitMiddleware(
  rateLimiterConfigs.verifyEmail
);
export const resendOtpRateLimitMiddleware = createRateLimitMiddleware(
  rateLimiterConfigs.resendOtp
);
export const forgotPasswordRateLimitMiddleware = createRateLimitMiddleware(
  rateLimiterConfigs.forgotPassword
);
export const refreshTokenRateLimitMiddleware = createRateLimitMiddleware(
  rateLimiterConfigs.refreshToken
);
