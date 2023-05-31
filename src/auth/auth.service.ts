import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  hashData(password: string) {
    return bcrypt.hashSync(password, 10);
  }

  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email },
        { secret: 'at-secret', expiresIn: 60 * 20 },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        { secret: 'rt-secret', expiresIn: 60 * 60 * 24 * 7 },
      ),
    ]);
    return {
      accessToken: at,
      refreshToken: rt,
    };
  }

  async updateRtHash(userId: string, rt: string) {
    const hash = await this.hashData(rt);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async localSignup(dto: AuthDto): Promise<Tokens> {
    const { email, name, password } = dto;
    const hashedPassword = this.hashData(password);
    const user = await this.prismaService.user.create({
      data: {
        email,
        name,
        hashedPassword: hashedPassword,
        hashedRt: '',
      },
    });
    const tokens = await this.getTokens(+user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    return tokens;
  }

  async localSignin(dto: AuthDto) {
    const { email, password } = dto;
    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });
    if (!user) throw new Error('User not found');
    const isPasswordValid = bcrypt.compareSync(password, user.hashedPassword);
    if (!isPasswordValid) throw new Error('Invalid password');
    const tokens = await this.getTokens(+user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    return tokens;
  }

  async signout(userId: string) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
    return 'signout';
  }

  async refresh(userId: string, rt: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user) throw new Error('User not found');
    const isRtValid = bcrypt.compareSync(rt, user.hashedRt);
    if (!isRtValid) throw new Error('Invalid refresh token');
    const tokens = await this.getTokens(+user.id, user.email);
    await this.updateRtHash(user.id, tokens.refreshToken);
    return tokens;
  }
}
