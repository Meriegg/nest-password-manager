import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthDto } from './dto/auth.dto'
import { Request, Response } from 'express'
import { RefreshTokenGuard } from './guards'

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: AuthDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.login(body, res)
  }

  @Post('register')
  async register(@Body() body: AuthDto, @Res({ passthrough: true }) res: Response) {
    return this.authService.register(body, res)
  }

  @UseGuards(RefreshTokenGuard)
  @Post('refreshToken')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authService.refreshToken(req, res)
  }
}
