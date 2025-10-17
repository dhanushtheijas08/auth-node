import { Verification_Type as VerificationType } from "@prisma/client";
import { prisma } from "../config/db";
import { verificationCodeGenerator } from "../utils/verificationCodeGenerator";

export const verificationCode = async (
  userId: string,
  verificationType: VerificationType
) => {
  const now = new Date();

  const existingCode = await prisma.verificationCode.findFirst({
    where: {
      userId,
      type: verificationType,
      expiresAt: { gt: now },
    },
  });

  if (existingCode) {
    return {
      ...existingCode,
      isNewCode: false,
    };
  }

  const code = verificationCodeGenerator(verificationType);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 5);

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
  };
};
