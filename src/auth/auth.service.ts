import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request, Response } from 'express'
import { PrismaService } from 'src/prisma/prisma.service'
import { AuthDto } from './dto/auth.dto'
import * as bcrypt from 'bcrypt'
import { Prisma } from '@prisma/client'
import { EncryptionService } from 'src/encryption/encryption.service'

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private crypto: EncryptionService,
  ) {}

  private createAccessToken(id: string): string {
    const token = this.jwt.sign({ id }, { expiresIn: '15min' })

    return token
  }

  private createRefreshToken(id: string): { token: string; cookieExpire: Date } {
    const token = this.jwt.sign({ id, isRefresh: true }, { expiresIn: '14d' })

    // Get todays date
    const today = new Date()

    // Create the expiry date
    const expire = new Date()

    // Set the expiry date to 14 days from now
    expire.setTime(today.getTime() + 3600000 * 24 * 14)

    return { token, cookieExpire: expire }
  }

  private async setRefreshTokenInDb(token: string, userId: string) {
    const encryptedToken = this.crypto.encrypt(token)

    const dbUser = await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: encryptedToken,
      },
    })

    return dbUser
  }

  private async deleteRefreshTokenInDb(userId: string) {
    const dbUser = await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: null,
      },
    })

    return dbUser
  }

  async login(body: AuthDto, res: Response) {
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
    })
    if (!existingUser) {
      throw new HttpException('Could not find user!', HttpStatus.NOT_FOUND)
    }

    const doPasswordsMatch = await bcrypt.compare(body.password, existingUser.password)
    if (!doPasswordsMatch) {
      throw new HttpException('Incorrect password!', HttpStatus.UNAUTHORIZED)
    }

    // Create access token
    const token = this.createAccessToken(existingUser.id)

    // Create refresh token
    const refreshToken = this.createRefreshToken(existingUser.id)

    // Set the refresh token in database
    const finalUser = await this.setRefreshTokenInDb(refreshToken.token, existingUser.id)

    // Set a cookie with the refresh token
    res.cookie('refreshToken', refreshToken.token, {
      httpOnly: true,
      expires: refreshToken.cookieExpire,
    })

    delete finalUser.password

    return { message: 'Logged in successfully!', user: finalUser, token }
  }

  async register(body: AuthDto, res: Response) {
    try {
      // hash password
      const hashedPass = await bcrypt.hash(body.password, 10)

      // Create and save user in database
      const newUser = await this.prisma.user.create({
        data: {
          email: body.email,
          password: hashedPass,
        },
      })

      // Create jwt token
      const token = this.createAccessToken(newUser.id)

      // Create a refresh token
      const refreshToken = this.createRefreshToken(newUser.id)

      // Set the refresh token in database
      const finalUser = await this.setRefreshTokenInDb(refreshToken.token, newUser.id)

      // Set a cookie with the refresh token
      res.cookie('refreshToken', refreshToken.token, {
        httpOnly: true,
        expires: refreshToken.cookieExpire,
      })

      delete finalUser.password

      return { user: finalUser, token, message: 'Registered successfully!' }
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        throw new HttpException('Email already taken!', HttpStatus.BAD_REQUEST)
      }

      throw new HttpException('Something went wrong', HttpStatus.BAD_REQUEST)
    }
  }

  async refreshToken(req: Request, res: Response) {
    if (!res.locals.refreshUserId) {
      throw new HttpException('Refresh token expired', HttpStatus.UNAUTHORIZED)
    }

    const newToken = this.createAccessToken(res.locals.refreshUserId)

    return { token: newToken }
  }
}
