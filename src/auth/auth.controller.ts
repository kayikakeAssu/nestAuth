import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Request,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  async localSignup(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.localSignup(dto);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  async localSignin(@Body() dto: AuthDto): Promise<Tokens> {
    return await this.authService.localSignin(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/signout')
  @HttpCode(HttpStatus.OK)
  async signout(@Req() req: Request) {
    const userId = await req.body['sub'];
    return this.authService.signout(userId);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request) {
    const user = await req.body;
    return this.authService.refresh(user['sub'], user['refreshToken']);
  }
}
