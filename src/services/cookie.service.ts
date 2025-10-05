import { Response } from "express";
import { env } from "../config/env";

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  expires?: Date;
  path?: string;
  domain?: string;
  maxAge?: number;
}

const defaultOptions: CookieOptions = {
  httpOnly: true,
  secure: env.NODE_ENV === "production",
  sameSite: "strict",
};

export const setAccessTokenCookie = (
  res: Response,
  token: string,
  options: Partial<CookieOptions> = {}
): Response => {
  const defaultAccessTokenOptions: CookieOptions = {
    ...defaultOptions,
    expires: new Date(Date.now() + 1000 * 60 * 10), // 10 minutes
  };

  const cookieOptions = { ...defaultAccessTokenOptions, ...options };

  return res.cookie("accessToken", token, cookieOptions);
};

export const setRefreshTokenCookie = (
  res: Response,
  token: string,
  options: Partial<CookieOptions> = {}
): Response => {
  const defaultRefreshTokenOptions: CookieOptions = {
    ...defaultOptions,
    expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 days
    path: "/refresh",
  };

  const cookieOptions = { ...defaultRefreshTokenOptions, ...options };

  return res.cookie("refreshToken", token, cookieOptions);
};

export const setTokenCookies = (
  res: Response,
  accessToken: string,
  refreshToken: string,
  options: {
    accessTokenOptions?: Partial<CookieOptions>;
    refreshTokenOptions?: Partial<CookieOptions>;
  } = {}
): Response => {
  return res
    .cookie("accessToken", accessToken, {
      ...defaultOptions,
      expires: new Date(Date.now() + 1000 * 60 * 10), // 10 minutes
      ...options.accessTokenOptions,
    })
    .cookie("refreshToken", refreshToken, {
      ...defaultOptions,
      expires: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30), // 30 days
      path: "/refresh",
      ...options.refreshTokenOptions,
    });
};

export const clearAccessTokenCookie = (res: Response): Response => {
  return res.clearCookie("accessToken", {
    ...defaultOptions,
  });
};

export const clearRefreshTokenCookie = (res: Response): Response => {
  return res.clearCookie("refreshToken", {
    ...defaultOptions,
    path: "/refresh",
  });
};

export const clearTokenCookies = (res: Response): Response => {
  return res
    .clearCookie("accessToken", {
      ...defaultOptions,
    })
    .clearCookie("refreshToken", {
      ...defaultOptions,
      path: "/refresh",
    });
};
