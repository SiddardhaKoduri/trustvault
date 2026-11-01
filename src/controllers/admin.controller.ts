import { Response } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { prisma } from '../lib/prisma.js';
import { AuditService } from '../services/audit.service.js';
import { AuthenticatedRequest } from '../types/index.js';

const UpdateStatusSchema = z.object({
  isActive: z.boolean(),
});

const CreateUserSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email(),
  password: z.string().min(8),
  role: z.enum(['ADMIN', 'OWNER', 'VIEWER']),
});

export class AdminController {
  /**
   * Lists all users in the vault with their account status and document metrics.
   * Access restricted to ADMIN role only.
   */
  static async listUsers(req: AuthenticatedRequest, res: Response) {
    if (!req.user || req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
    }

    try {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          isActive: true,
          permissionEpoch: true,
          createdAt: true,
          updatedAt: true,
          _count: {
            select: {
              ownedDocuments: true,
              permissions: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'ADMIN_USER_LIST_VIEWED',
        resourceType: 'SYSTEM',
        resourceId: 'USER_DIRECTORY',
        outcome: 'SUCCESS',
        reason: `Administrator listed ${users.length} accounts`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({ users });
    } catch (error) {
      console.error('List users error:', error);
      return res.status(500).json({ error: 'Failed to retrieve user directory.' });
    }
  }

  /**
   * Activates or deactivates a user account.
   * Instantaneous Revocation: Deactivation increments permissionEpoch, immediately cutting off sessions.
   */
  static async updateUserStatus(req: AuthenticatedRequest, res: Response) {
    if (!req.user || req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
    }

    const { id } = req.params;
    const parse = UpdateStatusSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: 'Invalid status parameter' });
    }

    const { isActive } = parse.data;

    // Prevent Admin from deactivating their own account
    if (id === req.user.id && !isActive) {
      return res.status(400).json({ error: 'Cannot deactivate your own administrator account.' });
    }

    try {
      const targetUser = await prisma.user.findUnique({ where: { id } });
      if (!targetUser) {
        return res.status(404).json({ error: 'User not found.' });
      }

      // If deactivating, increment permissionEpoch to invalidate any active session token
      const updated = await prisma.user.update({
        where: { id },
        data: {
          isActive,
          ...(isActive === false ? { permissionEpoch: { increment: 1 } } : {}),
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          isActive: true,
          permissionEpoch: true,
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'ADMIN_USER_STATUS_UPDATE',
        resourceType: 'USER',
        resourceId: id,
        outcome: 'SUCCESS',
        reason: `Admin changed active status of ${targetUser.email} to ${isActive}`,
        clientIp: req.clientIp,
      });

      return res.status(200).json({
        message: `User account ${isActive ? 'activated' : 'deactivated'} successfully.`,
        user: updated,
      });
    } catch (error) {
      console.error('Update user status error:', error);
      return res.status(500).json({ error: 'Failed to update user status.' });
    }
  }

  /**
   * Admin-provisioned user creation.
   * Admins can create other Admins, Owners, or Viewers.
   */
  static async createUser(req: AuthenticatedRequest, res: Response) {
    if (!req.user || req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied: Administrator privileges required.' });
    }

    const parse = CreateUserSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: 'Invalid user parameters', details: parse.error.format() });
    }

    const name = parse.data.name.trim();
    const email = parse.data.email.toLowerCase().trim();
    const { password, role } = parse.data;

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
          isActive: true,
          permissionEpoch: 1,
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          isActive: true,
          createdAt: true,
        },
      });

      await AuditService.recordEvent({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'ADMIN_USER_CREATED',
        resourceType: 'USER',
        resourceId: user.id,
        outcome: 'SUCCESS',
        reason: `Administrator created new account for ${email} with role ${role}`,
        clientIp: req.clientIp,
      });

      return res.status(201).json({
        message: 'User created successfully',
        user,
      });
    } catch (error) {
      console.error('Admin create user error:', error);
      return res.status(500).json({ error: 'Failed to create user.' });
    }
  }
}
