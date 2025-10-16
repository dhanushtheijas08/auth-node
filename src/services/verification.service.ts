import { Verification_Type as VerificationType } from "@prisma/client";
import { prisma } from "../config/db";
import { verificationCodeGenerator } from "../utils/verificationCodeGenerator";

export const verificationCode = async (
  userId: string,
  verificationType: VerificationType
) => {
  const code = verificationCodeGenerator(verificationType);

  const existingCode = await prisma.verificationCode.findFirst({
    where: { userId, type: verificationType, expiresAt: { gt: new Date() } },
  });

  if (existingCode) {
    return existingCode;
  }

  const verificationCode = await prisma.verificationCode.create({
    data: {
      code: code,
      type: verificationType,
      expiresAt: new Date(Date.now() + 1000 * 60 * 5),
      userId: userId,
    },
  });

  return verificationCode;
};
