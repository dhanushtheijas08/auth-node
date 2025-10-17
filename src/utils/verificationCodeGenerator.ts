import crypto from "crypto";
import { Verification_Type } from "@prisma/client";

export const verificationCodeGenerator = (type: Verification_Type) => {
  if (type === "VERIFY_EMAIL") {
    return crypto.randomInt(100000, 999999).toString();
  }
  return crypto.randomBytes(3).toString("hex").toUpperCase();
};
