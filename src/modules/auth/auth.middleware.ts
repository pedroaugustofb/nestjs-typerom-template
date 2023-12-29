import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NextFunction, Request, Response } from 'express';
import { verify } from 'jsonwebtoken';

@Injectable()
export default class AuthMiddleware implements NestMiddleware {
  private logger = new Logger();

  private config = new ConfigService();

  use(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization;

    // here you can do whatever you want with the authorization header

    // sugestion with JWT
    // - check if the authorization header is valid
    // - check if the user exists in the database

    // example: Bearer 1234567890

    if (!token) throw new Error('Authorization header is required');

    if (!token.startsWith('Bearer')) throw new Error('Authorization header must start with Bearer');

    if (token.split(' ').length !== 2) throw new Error('Authorization header must have 2 parts');

    const hash = token?.split(' ')[1]; // 1234567890

    verify(hash, this.config.get('JWT_SECRET'), (err, decoded) => {
      if (err) {
        this.logger.error(`error on auth middleware > Invalid token > ${err}`);
        return res.status(500).json({ status: 500, message: 'Internal Server Error' });
      }

      // here you can do whatever you want with the decoded token

      // sugestion with JWT
      // - check if the user exists in the database
      // - check if the user has the permission to access the route

      // example: { sub: '1234567890', iat: 1516239022 }

      this.logger.log(`decoded token: ${JSON.stringify(decoded)}`);

      return next();
    });
  }
}
