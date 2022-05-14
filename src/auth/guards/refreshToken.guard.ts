import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request, Response } from 'express'
import { EncryptionService } from 'src/encryption/encryption.service'
import { PrismaService } from 'src/prisma/prisma.service'

@Injectable()
export class RefreshTokenGuard implements CanActivate {
  constructor(
    private jwt: JwtService,
    private crypto: EncryptionService,
    private prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    try {
      const req: Request = context.switchToHttp().getRequest()
      const res: Response = context.switchToHttp().getResponse()
      const token = req.cookies['refreshToken']

      // Check if token exists
      if (!token) {
        return false
      }

      // Verify and decode the token
      const decoded: any = this.jwt.verify(token)

      // Check if the token is a refresh token
      if (!decoded.isRefresh) {
        return false
      }

      // Check if the token is expired
      // If the token is expired delete the refresh token stored in database
      if (Date.now() >= decoded?.exp * 1000) {
        await this.prisma.user.update({
          data: {
            refreshToken: null,
          },
          where: {
            id: decoded.id,
          },
        })

        return false
      }

      // Set the user id from the token
      res.locals.refreshUserId = decoded?.id

      // Check if the refresh token is the same as the one stored in database
      const databaseUser = await this.prisma.user.findUnique({
        where: {
          id: decoded?.id,
        },
      })

      const decryptedRefreshToken = this.crypto.decrypt(databaseUser.refreshToken)

      if (token !== decryptedRefreshToken) {
        return false
      }

      return true
    } catch (error) {
      return false
    }
  }
}
