import * as jose from "jose";
import { env } from "../config/env";
import { ApiError } from "../utils/ApiError";

const secret = new TextEncoder().encode(env.JWT_SECRET);

export interface TokenPayload {
  userId: string;
  role: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export const generateAccessToken = async (
  payload: TokenPayload,
  sessionId: string,
  expirationTime: string = "10m"
): Promise<string> => {
  return await new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(expirationTime)
    .setJti(sessionId)
    .sign(secret);
};

export const generateRefreshToken = async (
  payload: TokenPayload,
  sessionId: string,
  expirationTime: string = "30d"
): Promise<string> => {
  return await new jose.SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(expirationTime)
    .setJti(sessionId)
    .sign(secret);
};

export const generateTokenPair = async (
  payload: TokenPayload,
  sessionId: string
): Promise<TokenPair> => {
  const [accessToken, refreshToken] = await Promise.all([
    generateAccessToken(payload, sessionId),
    generateRefreshToken(payload, sessionId),
  ]);

  return {
    accessToken,
    refreshToken,
  };
};

export const verifyToken = async (token: string): Promise<jose.JWTPayload> => {
  const { payload } = await jose.jwtVerify(token, secret);
  return payload;
};
