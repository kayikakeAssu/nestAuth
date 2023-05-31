import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { type } from 'os';
import { Strategy, ExtractJwt } from 'passport-jwt';

type jwtPayload = {
  sub: string;
  email: string;
};

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'at-secret',
    });
  }
  async validate(payload: jwtPayload) {
    return payload;
  }
}
