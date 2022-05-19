import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { AuthModule } from './auth/auth.module'
import { EncryptionModule } from './encryption/encryption.module'
import { PasswordModule } from './password/password.module'
import { PrismaModule } from './prisma/prisma.module'
import { UserModule } from './user/user.module'

@Module({
  imports: [
    AuthModule,
    PrismaModule,
    EncryptionModule,
    PasswordModule,
    UserModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
  ],
})
export class AppModule {}
