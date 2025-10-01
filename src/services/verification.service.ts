import { Verification_Type as VerificationType } from "@prisma/client";
import { prisma } from "../config/db";
import { verificationCodeGenerator } from "../utils/verificationCodeGenerator";

export const verificationCode = async (
  userId: string,
  verificationType: VerificationType
) => {
  const code = verificationCodeGenerator(verificationType);
  const verificationCode = await prisma.verificationCode.create({
    data: {
      code: code,
      type: verificationType,
      expiresAt: new Date(Date.now() + 1000 * 60 * 15),
      userId: userId,
    },
  });

  return verificationCode;
};
