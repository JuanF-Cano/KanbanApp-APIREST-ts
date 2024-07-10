import { Request, Response, NextFunction } from 'express';
import { jwtVerify, JWTVerifyResult } from "jose";
import dotenv from 'dotenv';

dotenv.config();

interface AuthenticatedRequest extends Request {
  user?: any;
}

const authenticateToken = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  const { authorization } = req.headers;

  if (!authorization) {
    res.status(401).send('Token no proporcionado');
    return;
  }

  try {
    const encoder = new TextEncoder();
    const secret = process.env.secret;
    
    if (!secret) {
      throw new Error('Secret is not defined in environment variables');
    }

    const { payload }: JWTVerifyResult = await jwtVerify(authorization, encoder.encode(secret));
    req.user = payload;
    next();
  } catch (err) {
    console.error(err);
    res.status(401).send('Token inválido o expirado');
  }
};

export { authenticateToken };