import { HttpException, HttpStatus, Injectable } from '@nestjs/common'
import { Response } from 'express'
import { PrismaService } from 'src/prisma/prisma.service'
import { ChangePasswordDto } from './dto'
import * as bcrypt from 'bcrypt'

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async changePassword(body: ChangePasswordDto, res: Response) {
    const hashedPassword = await bcrypt.hash(body.newPassword, 10)

    const updatedUser = await this.prisma.user.update({
      where: {
        id: res.locals.userId,
      },
      data: {
        password: hashedPassword,
      },
    })

    delete updatedUser.password

    return { message: 'Password updated successfully!', newUser: updatedUser }
  }

  async getMyData(res: Response) {
    const dbUser = await this.prisma.user.findUnique({
      where: {
        id: res.locals.userId,
      },
      include: {
        passwords: true,
      },
    })
    if (!dbUser) {
      throw new HttpException('Could not find user!', HttpStatus.NOT_FOUND)
    }

    return { user: dbUser }
  }
}
