import dotenv from "dotenv";
dotenv.config();

const getEnv = (key: string) => {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required env variable: ${key}`);

  return val as string;
};

export const env = {
  PORT: getEnv("PORT"),
  DATABASE_URL: getEnv("DATABASE_URL"),
  REDIS_URL: getEnv("REDIS_URL"),
  MAIL_API_KEY: getEnv("MAIL_API_KEY"),
  // FROM_EMAIL: getEnv("FROM_EMAIL"),
  JWT_SECRET: getEnv("JWT_SECRET"),
  NODE_ENV: getEnv("NODE_ENV"),
};
