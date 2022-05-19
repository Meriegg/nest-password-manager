import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import { Response } from 'express'
import { EncryptionService } from 'src/encryption/encryption.service'
import { PrismaService } from 'src/prisma/prisma.service'
import { PasswordDto, UpdatePasswordDto } from './dto/password.dto'

@Injectable()
export class PasswordService {
  constructor(private prisma: PrismaService, private crypto: EncryptionService) {}

  async createPassword(body: PasswordDto, res: Response) {
    try {
      const newPassword = await this.prisma.password.create({
        data: {
          content: this.crypto.encrypt(body.content),
          platform: body.platform ? this.crypto.encrypt(body.platform) : null,
          platformUsername: body.platformUser
            ? this.crypto.encrypt(body.platformUser)
            : null,
          ownerId: res.locals.userId,
        },
      })

      return newPassword
    } catch (error) {
      console.error(error)

      throw error
    }
  }

  async getAllPasswords(res: Response) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: res.locals.userId,
      },
      include: {
        passwords: true,
      },
    })
    if (!user.passwords) {
      throw new HttpException('Could not get any passwords!', HttpStatus.NOT_FOUND)
    }

    let decryptedPasswords = []

    user.passwords.forEach((password) => {
      decryptedPasswords.push({
        content: this.crypto.decrypt(password.content),
        platform: this.crypto.decrypt(password.platform),
        platformUsername: this.crypto.decrypt(password.platformUsername),
        id: password.id,
      })
    })

    return { passwords: decryptedPasswords }
  }

  async deletePassword(passwordId: string, res: Response) {
    const existingPass = await this.prisma.password.findUnique({
      where: {
        id: passwordId,
      },
    })

    if (existingPass.ownerId !== res.locals.userId) {
      throw new HttpException('Unauthorized!', HttpStatus.UNAUTHORIZED)
    }

    const deletedPassword = await this.prisma.password.delete({
      where: {
        id: passwordId,
      },
    })

    return { message: 'Password deleted successfully!', deletedPassword }
  }

  async updatePassword(body: UpdatePasswordDto, passwordId: string) {
    const updatedPassword = await this.prisma.password.update({
      data: {
        content: this.crypto.encrypt(body.content),
        platform: this.crypto.encrypt(body.platform),
        platformUsername: this.crypto.encrypt(body.platformUser),
      },
      where: {
        id: passwordId,
      },
    })

    return { message: 'Password updated successfully!', updatedPassword }
  }

  async getPassword(passwordId: string) {
    const password = await this.prisma.password.findUnique({
      where: {
        id: passwordId,
      },
    })

    return password
  }
}
