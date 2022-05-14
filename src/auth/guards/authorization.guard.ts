import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { Request, Response } from 'express'
import { Observable } from 'rxjs'

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(private jwt: JwtService) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    try {
      const req: Request = context.switchToHttp().getRequest()
      const res: Response = context.switchToHttp().getResponse()
      const token = req.headers['authorization'].split(' ')[1]

      if (!token) {
        return false
      }

      const decoded = this.jwt.verify(token)

      if (Date.now() >= decoded?.exp * 1000) {
        return false
      }

      res.locals.userId = decoded?.id

      return true
    } catch (error) {
      return false
    }
  }
}
