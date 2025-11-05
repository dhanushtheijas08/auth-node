import { z } from "zod";
import { Verification_Type } from "@prisma/client";

export const loginSchema = z.object({
  email: z.email("Invalid email").trim().toLowerCase(),
  password: z
    .string()
    .trim()
    .min(8, "Password must be at least 8 characters")
    .max(225, "Password must be less than 225 characters"),
});

export const registerSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(1, "Name is required")
      .max(50, "Name must be less than 50 characters"),
  })
  .extend(loginSchema.shape);

export const resendOtpSchema = z.object({
  email: z.email("Invalid email").trim().toLowerCase(),
  verificationType: z.enum(Verification_Type).default("VERIFY_EMAIL"),
});

export const forgortPasswordSchme = resendOtpSchema;

export const resetPasswordSchme = z
  .object({
    code: z.string().trim().length(6, "Code must be 6 characters"),
  })
  .extend(loginSchema.shape);

export const verifyEmailQuerySchema = z.object({
  email: z.email("Invalid email").trim().toLowerCase(),
  verificationType: z.enum(Verification_Type),
});

export const verifyEmailBodySchema = z.object({
  code: z.string().trim().length(6, "Code must be 6 characters"),
});
