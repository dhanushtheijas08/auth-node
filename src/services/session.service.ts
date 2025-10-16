import { Request } from "express";
import { prisma } from "../config/db";
import { Session } from "@prisma/client";

export const extractClientInfo = (
  req: Request
): { ipAddress: string; userAgent: string } => {
  const ipAddress =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0] ||
    req.socket.remoteAddress ||
    "0";
  const userAgent = req.headers["user-agent"] || "unknown";

  return { ipAddress, userAgent };
};

export const createSession = async (
  userId: string,
  req: Request,
  expirationDays: number = 30
): Promise<Session> => {
  const { ipAddress, userAgent } = extractClientInfo(req);

  const session = await prisma.session.create({
    data: {
      userId,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * expirationDays),
      ipAddress,
      userAgent,
    },
  });

  return session;
};
