import { ValidationPipe } from '@nestjs/common'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'
import * as cookieParser from 'cookie-parser'

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    cors: { credentials: true, origin: 'http://localhost:3000' },
  })
  // app.enableCors({ credentials: true, origin: 'http://localhost:3000' })
  app.use(cookieParser())
  app.useGlobalPipes(new ValidationPipe({}))
  await app.listen(5000)
}
bootstrap()
