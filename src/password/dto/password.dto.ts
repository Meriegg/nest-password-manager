import { IsString, IsNotEmpty } from 'class-validator'

export class PasswordDto {
  @IsString()
  @IsNotEmpty()
  content: string

  @IsString()
  platform: string

  @IsString()
  platformUser: string
}

export class UpdatePasswordDto {
  @IsString()
  content?: string

  @IsString()
  platform?: string

  @IsString()
  platformUser?: string
}
