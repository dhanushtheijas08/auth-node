import { Verification_Type } from "@prisma/client";

export const verificationCodeGenerator = (type: Verification_Type) => {
  if (type === "VERIFY_EMAIL") {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let code = "";
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
};
