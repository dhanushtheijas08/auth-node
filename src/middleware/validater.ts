import { NextFunction, Request, Response } from "express";
import { z } from "zod";

type ValidatorType = {
  body?: z.ZodTypeAny;
  query?: z.ZodTypeAny;
  params?: z.ZodTypeAny;
};

export const validator =
  ({ body, query, params }: ValidatorType) =>
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (body) await body.parseAsync(req.body);
      if (query) await query.parseAsync(req.query);
      if (params) await params.parseAsync(req.params);

      next();
    } catch (error) {
      let err = error;
      if (err instanceof z.ZodError) {
        const formattedErrors = err.issues.map((e) => ({
          path: e.path.join("."),
          message: e.message,
        }));
        res.status(400).json({ status: "error", message: formattedErrors });
      }
      next(error);
    }
  };
