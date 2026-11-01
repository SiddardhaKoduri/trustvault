import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { prisma } from '../lib/prisma.js';
import { AuthenticatedRequest, SessionUser, UserRole } from '../types/index.js';

const JWT_SECRET = process.env.JWT_SECRET || 'trustvault_development_jwt_secret_key_918237198273';

export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  try {
    // 1. Extract token from HTTP-only cookie or Bearer header
    let token = req.cookies?.token;
    if (!token && req.headers.authorization?.startsWith('Bearer ')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ error: 'Authentication required. No session token provided.' });
    }

    // 2. Verify cryptographic signature of JWT
    const decoded = jwt.verify(token, JWT_SECRET) as {
      id: string;
      email: string;
      permissionEpoch: number;
    };

    // 3. Instant Revocation Check: Validate user state directly against database
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isActive: true,
        permissionEpoch: true,
      },
    });

    if (!user) {
      res.clearCookie('token');
      return res.status(401).json({ error: 'User account no longer exists.' });
    }

    if (!user.isActive) {
      res.clearCookie('token');
      return res.status(403).json({ error: 'Account has been deactivated.' });
    }

    // Zero-Delay Revocation: If epoch has been bumped, old token is instantly invalid!
    if (user.permissionEpoch !== decoded.permissionEpoch) {
      res.clearCookie('token');
      return res.status(401).json({ error: 'Session invalidated due to permission change. Please sign in again.' });
    }

    req.user = user as SessionUser;
    req.clientIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';

    next();
  } catch (error) {
    res.clearCookie('token');
    return res.status(401).json({ error: 'Invalid or expired session token.' });
  }
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Forbidden: Requires one of [${allowedRoles.join(', ')}] roles.`,
      });
    }

    next();
  };
}
