import { Module } from '@nestjs/common'
import { AuthModule } from 'src/auth/auth.module'
import { PasswordController } from './password.controller'
import { PasswordService } from './password.service'

@Module({
  controllers: [PasswordController],
  providers: [PasswordService],
  imports: [AuthModule],
})
export class PasswordModule {}
