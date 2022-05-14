import { IsEmail, IsString, IsNotEmpty } from 'class-validator'

export class AuthDto {
  @IsEmail()
  @IsString()
  @IsNotEmpty()
  email: string

  @IsNotEmpty()
  @IsString()
  password: string
}
