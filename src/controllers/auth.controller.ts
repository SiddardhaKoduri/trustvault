import { Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';
import { AuthenticatedRequest } from '../types/index.js';

const JWT_SECRET = process.env.JWT_SECRET || 'trustvault_development_jwt_secret_key_918237198273';
const COOKIE_NAME = 'token';

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

const RegisterSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email(),
  password: z.string().min(8, 'Password must be at least 8 characters long'),
  role: z.enum(['ADMIN', 'OWNER', 'VIEWER']).default('VIEWER'),
});

export class AuthController {
  static async login(req: AuthenticatedRequest, res: Response) {
    const parse = LoginSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: 'Invalid input', details: parse.error.format() });
    }

    const email = parse.data.email.toLowerCase().trim();
    const { password } = parse.data;
    const clientIp = req.clientIp || (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';

    try {
      const user = await prisma.user.findUnique({ where: { email } });

      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        // Record failed authentication attempt in audit trail
        await AuditService.recordEvent({
          userEmail: email,
          action: 'AUTH_LOGIN_FAILED',
          resourceType: 'USER',
          resourceId: user?.id || 'UNKNOWN',
          outcome: 'DENIED',
          reason: 'INVALID_CREDENTIALS',
          clientIp,
          userAgent,
        });
        return res.status(401).json({ error: 'Invalid email or password.' });
      }

      if (!user.isActive) {
        await AuditService.recordEvent({
          userId: user.id,
          userEmail: email,
          action: 'AUTH_LOGIN_FAILED',
          resourceType: 'USER',
          resourceId: user.id,
          outcome: 'DENIED',
          reason: 'USER_DEACTIVATED',
          clientIp,
          userAgent,
        });
        return res.status(403).json({ error: 'Account has been deactivated.' });
      }

      // Generate signed JWT with permissionEpoch for instant invalidation capability
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role,
          permissionEpoch: user.permissionEpoch,
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      // Set secure HTTP-only cookie
      res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Record successful login in audit trail
      await AuditService.recordEvent({
        userId: user.id,
        userEmail: user.email,
        action: 'AUTH_LOGIN_SUCCESS',
        resourceType: 'USER',
        resourceId: user.id,
        outcome: 'SUCCESS',
        clientIp,
        userAgent,
      });

      return res.status(200).json({
        message: 'Authentication successful',
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
        token,
      });
    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({ error: 'Internal server error during authentication.' });
    }
  }

  static async register(req: AuthenticatedRequest, res: Response) {
    const parse = RegisterSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: 'Invalid registration details', details: parse.error.format() });
    }

    const name = parse.data.name.trim();
    const email = parse.data.email.toLowerCase().trim();
    const { password, role } = parse.data;
    const clientIp = req.clientIp || (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';

    // Zero-Trust Rule: Self-assignment of ADMIN role via public registration is STRICTLY PROHIBITED
    if (role === 'ADMIN') {
      await AuditService.recordEvent({
        userEmail: email,
        action: 'PRIVILEGE_ESCALATION_ATTEMPT',
        resourceType: 'USER',
        resourceId: 'ANONYMOUS',
        outcome: 'DENIED',
        reason: 'UNAUTHORIZED_ADMIN_REGISTRATION_ATTEMPT',
        clientIp,
      });
      return res.status(403).json({
        error: 'Forbidden: Self-registration of Administrator accounts is prohibited.',
      });
    }

    try {
      const existing = await prisma.user.findUnique({ where: { email } });
      if (existing) {
        return res.status(409).json({ error: 'User with this email already exists.' });
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const user = await prisma.user.create({
        data: {
          name,
          email,
          passwordHash,
          role,
        },
        select: {
          id: true,
          email: true,
          name: true,
          role: true,
          createdAt: true,
        },
      });

      await AuditService.recordEvent({
        userId: user.id,
        userEmail: user.email,
        action: 'USER_REGISTERED',
        resourceType: 'USER',
        resourceId: user.id,
        outcome: 'SUCCESS',
        clientIp,
      });

      return res.status(201).json({
        message: 'Account registered successfully',
        user,
      });
    } catch (error) {
      console.error('Registration error:', error);
      return res.status(500).json({ error: 'Registration failed.' });
    }
  }

  static async logout(req: AuthenticatedRequest, res: Response) {
    if (req.user) {
      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'AUTH_LOGOUT',
        resourceType: 'USER',
        resourceId: req.user.id,
        outcome: 'SUCCESS',
        clientIp: req.clientIp,
      });
    }

    res.clearCookie(COOKIE_NAME);
    return res.status(200).json({ message: 'Successfully logged out.' });
  }

  static async me(req: AuthenticatedRequest, res: Response) {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated.' });
    }
    return res.status(200).json({ user: req.user });
  }
}
