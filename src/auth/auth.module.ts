import { Module } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { AuthController } from './auth.controller'
import { AuthService } from './auth.service'

const JWT_CONFIG = JwtModule.registerAsync({
  imports: [ConfigService],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    secret: config.get('JWT_SECRET'),
  }),
})

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [JWT_CONFIG],
  exports: [JWT_CONFIG],
})
export class AuthModule {}
