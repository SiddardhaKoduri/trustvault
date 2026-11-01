import { Request } from 'express';

export type UserRole = 'ADMIN' | 'OWNER' | 'VIEWER';
export type PermissionLevel = 'READ' | 'EDIT';
export type AuditOutcome = 'SUCCESS' | 'DENIED';

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  isActive: boolean;
  permissionEpoch: number;
}

export interface AuthenticatedRequest extends Request {
  user?: SessionUser;
  clientIp?: string;
}

export interface AuthorizationResult {
  authorized: boolean;
  statusCode?: number;
  reason?: string;
  document?: any;
  accessLevel?: PermissionLevel | 'OWNER';
}
