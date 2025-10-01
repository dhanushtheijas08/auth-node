import { Request, Response } from "express";
import { ApiError } from "../utils/ApiError";

export const errorHandler = (err: any, req: Request, res: Response) => {
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      status: "error",
      message: err.message,
      redirectRoute: err.redirectRoute || null,
    });
  }

  if (err.code === "P2002") {
    return res
      .status(400)
      .json({ status: "error", message: "Duplicate value detected" });
  }

  return res
    .status(500)
    .json({ status: "error", message: "Internal Server Error" });
};
