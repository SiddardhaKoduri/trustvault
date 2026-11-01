import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/index.js';
import { AuditService } from '../services/audit.service.js';

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  actionName: string;
}) {
  const store: RateLimitStore = {};

  // Periodically clean up expired entries
  setInterval(() => {
    const now = Date.now();
    for (const key in store) {
      if (store[key].resetTime < now) {
        delete store[key];
      }
    }
  }, options.windowMs).unref();

  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const clientIp = req.clientIp || req.socket.remoteAddress || '127.0.0.1';
    const key = `${options.actionName}:${clientIp}`;
    const now = Date.now();

    if (!store[key] || store[key].resetTime < now) {
      store[key] = {
        count: 1,
        resetTime: now + options.windowMs,
      };
      return next();
    }

    store[key].count++;

    if (store[key].count > options.maxRequests) {
      // Record rate limit violation in cryptographic audit trail
      await AuditService.recordEvent({
        action: 'RATE_LIMIT_EXCEEDED',
        resourceType: 'SYSTEM',
        resourceId: options.actionName,
        outcome: 'DENIED',
        reason: `RATE_LIMIT: IP ${clientIp} exceeded ${options.maxRequests} requests per ${options.windowMs / 1000}s`,
        clientIp,
      });

      const retryAfter = Math.ceil((store[key].resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: `Too many requests for ${options.actionName}. Please try again in ${retryAfter} seconds.`,
      });
    }

    next();
  };
}
