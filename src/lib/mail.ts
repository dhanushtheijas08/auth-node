import nodemailer from "nodemailer";
import { env } from "../config/env";
import { emailTemplate } from "../utils/emailTemplate";
import { Verification_Type as VerificationType } from "@prisma/client";

export const sendMail = async (
  verificationType: VerificationType,
  code: string
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

  await transporter.sendMail({
    from: "onboarding@resend.dev",
    to: "delivered@resend.dev",
    subject: "Hello World",
    html: emailTemplate(verificationType, code),
  });
};
