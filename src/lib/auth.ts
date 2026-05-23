import jwt from "jsonwebtoken";

export interface JwtPayload {
  userId: number;
  roleId: number;
  iat?: number;
  exp?: number;
}

export const ADMIN_ROLE_ID = Number(process.env.ADMIN_ROLE_ID || 1);

export function getTokenFromHeader(authorization?: string) {
  if (!authorization) return null;
  const [scheme, token] = authorization.split(" ");
  if (scheme !== "Bearer" || !token) return null;
  return token;
}

export function verifyJwt(token: string) {
  const secret = process.env.JWT_SECRET || "your_jwt_secret";
  return jwt.verify(token, secret) as JwtPayload;
}
