import { Verification_Type as VerificationType } from "@prisma/client";
import { prisma } from "../config/db";
import { verificationCodeGenerator } from "../utils/verificationCodeGenerator";

const ONE_MINUTE_IN_MS = 60 * 1000;
const OTP_EXPIRY_TIME_MS = 5 * 60 * 1000;

export const verificationCode = async (
  userId: string,
  verificationType: VerificationType
) => {
  const now = new Date();
  const oneMinuteAgo = new Date(Date.now() - ONE_MINUTE_IN_MS);

  // Check if there's an existing code (regardless of expiry)
  const existingCode = await prisma.verificationCode.findFirst({
    where: {
      userId,
      type: verificationType,
    },
    orderBy: {
      createdAt: "desc",
    },
  });

  // If there's an existing code created within the last 1 minute AND not expired, return it with extended expiry
  if (
    existingCode &&
    existingCode.createdAt > oneMinuteAgo &&
    existingCode.expiresAt > now
  ) {
    // Just extend the expiry time, don't create a new code
    const updatedCode = await prisma.verificationCode.update({
      where: { id: existingCode.id },
      data: {
        expiresAt: new Date(Date.now() + OTP_EXPIRY_TIME_MS),
      },
    });

    return {
      ...updatedCode,
      isNewCode: false,
      shouldSendEmail: false,
    };
  }

  // If code is older than 1 minute, expired, or doesn't exist, create a new one
  const code = verificationCodeGenerator(verificationType);
  const expiresAt = new Date(Date.now() + OTP_EXPIRY_TIME_MS);

  const newCode = await prisma.verificationCode.create({
    data: {
      code,
      type: verificationType,
      expiresAt,
      userId,
    },
  });

  return {
    ...newCode,
    isNewCode: true,
    shouldSendEmail: true,
  };
};
