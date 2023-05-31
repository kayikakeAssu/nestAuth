import { IsEmail, IsString, IsNotEmpty, IsOptional } from 'class-validator';

export class AuthDto {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsString()
  @IsOptional()
  name: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
