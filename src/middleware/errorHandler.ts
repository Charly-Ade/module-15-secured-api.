import { Request, Response, NextFunction } from "express";
import { AppError, UnauthorizedError, ValidationError } from "./errors";

export const notFoundHandler = (_req: Request, res: Response): void => {
  res.status(404).json({ message: "Route not found" });
};

 
export const errorHandler = (
  error: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void => {
  if (error instanceof AppError) {
    if (error instanceof UnauthorizedError) {
      res.setHeader("WWW-Authenticate", "Bearer");
    }
    res.status(error.statusCode).json({
      message: error.message,
      ...(error instanceof ValidationError && error.details !== undefined
        ? { details: error.details }
        : {}),
    });
    return;
  }

  // Errors raised by express.json(): malformed body / body too large.
  const type = (error as { type?: string } | null)?.type;
  if (type === "entity.parse.failed") {
    res.status(400).json({ message: "Malformed JSON body" });
    return;
  }
  if (type === "entity.too.large") {
    res.status(413).json({ message: "Request body too large" });
    return;
  }

  // Unknown error: log server-side, never leak internals (stack, messages) to the client.
  console.error(error);
  res.status(500).json({ message: "Internal server error" });
};
