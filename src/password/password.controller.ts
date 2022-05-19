import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common'
import { Response } from 'express'
import { AuthorizationGuard } from '../auth/guards/index'
import { PasswordDto, UpdatePasswordDto } from './dto/password.dto'
import { PasswordService } from './password.service'

@UseGuards(AuthorizationGuard)
@Controller('password')
export class PasswordController {
  constructor(private passwordService: PasswordService) {}

  @Post('createPassword')
  async createPassword(
    @Body() body: PasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.passwordService.createPassword(body, res)
  }

  @Get('getAllPasswords')
  async getAllPasswords(@Res({ passthrough: true }) res: Response) {
    return this.passwordService.getAllPasswords(res)
  }

  @Get('getPassword/:passwordId')
  async getPassword(@Param('passwordId') passwordId: string) {
    return this.passwordService.getPassword(passwordId)
  }

  @Delete(':passwordId')
  async deletePassword(
    @Param('passwordId') passwordId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.passwordService.deletePassword(passwordId, res)
  }

  @Patch('updatePassword/:passwordId')
  async updatePassword(
    @Body() body: UpdatePasswordDto,
    @Param('passwordId') passwordId: string,
  ) {
    return this.passwordService.updatePassword(body, passwordId)
  }
}
