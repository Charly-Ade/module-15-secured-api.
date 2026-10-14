import { NextFunction, Request, Response } from "express";

/** In production the app sits behind a TLS-terminating proxy (trust proxy is set), so
 *  `req.secure` reflects X-Forwarded-Proto. Plain-HTTP requests are redirected (GET/HEAD) or
 *  refused (everything else, so credentials are never accepted over HTTP). */
export const createHttpsEnforcer =
  (enabled: boolean) =>
  (req: Request, res: Response, next: NextFunction): void => {
    if (!enabled || req.secure) {
      next();
      return;
    }
    if (req.method === "GET" || req.method === "HEAD") {
      res.redirect(308, `https://${req.headers.host ?? ""}${req.originalUrl}`);
      return;
    }
    res.status(403).json({ message: "HTTPS is required" });
  };
