import nodemailer from "nodemailer";
import { env } from "../config/env";
import { emailTemplate } from "../utils/emailTemplate";
import { Verification_Type as VerificationType } from "@prisma/client";

export const sendMail = async (
  verificationType: VerificationType,
  code: string,
  userEmail: string
) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.resend.com",
    secure: true,
    port: 465,
    auth: {
      user: "resend",
      pass: env.MAIL_API_KEY,
    },
  });

  const subject =
    verificationType === "VERIFY_EMAIL"
      ? "Verify Your Email Address"
      : "Your Verification Code";

  await transporter.sendMail({
    from: "Acme <onboarding@resend.dev>",
    // to: userEmail,
    to: "delivered@resend.dev",
    subject: subject,
    html: emailTemplate(verificationType, code),
  });
};
