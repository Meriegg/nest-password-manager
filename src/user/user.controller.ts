import { Body, Controller, Get, Patch, Res, UseGuards } from '@nestjs/common'
import { Response } from 'express'
import { AuthorizationGuard } from 'src/auth/guards'
import { ChangePasswordDto } from './dto'
import { UserService } from './user.service'

@UseGuards(AuthorizationGuard)
@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Patch('changePassword')
  async changePassword(
    @Res({ passthrough: true }) res: Response,
    @Body() body: ChangePasswordDto,
  ) {
    return this.userService.changePassword(body, res)
  }

  @Get('getMyData')
  async getMyData(@Res({ passthrough: true }) res: Response) {
    return this.userService.getMyData(res)
  }
}
