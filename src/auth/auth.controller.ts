import {
  Body,
  Controller,
  Get,
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
import { AuthorizationGuard, RefreshTokenGuard } from './guards'

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

  @UseGuards(AuthorizationGuard)
  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    return this.authService.logout(res)
  }

  @UseGuards(RefreshTokenGuard)
  @Get('refreshToken')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    return this.authService.refreshToken(req, res)
  }
}
