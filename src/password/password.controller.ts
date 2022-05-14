import { Controller, Get, Res, UseGuards } from '@nestjs/common'
import { Response } from 'express'
import { AuthorizationGuard } from '../auth/guards/index'

@Controller('password')
export class PasswordController {
  @Get('test')
  @UseGuards(AuthorizationGuard)
  async testRoute(@Res({ passthrough: true }) res: Response) {
    return 'test route'
  }
}
