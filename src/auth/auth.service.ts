import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtPayload, TokenOptions, Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

const FIFTEEN_MINUTES = 60 * 15;
const ONE_WEEK = 60 * 60 * 24 * 7;

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(data: AuthDto): Promise<Tokens> {
    const passwordHash = await this.generateHash(data.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: data.email,
        password: passwordHash,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    this.updateRefreshTokenHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(data: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: data.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Access Denied!');
    }

    const passwordValid = await bcrypt.compare(data.password, user.password);
    if (!passwordValid) throw new ForbiddenException('Access Denied!');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashRefreshToken: {
          not: null,
        },
      },
      data: {
        hashRefreshToken: null,
      },
    });
  }

  async refreshTokens(userId: number, refreshToken: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashRefreshToken) {
      throw new ForbiddenException('Access Denied!');
    }

    const refreshTokenValid = await bcrypt.compare(
      refreshToken,
      user.hashRefreshToken,
    );

    if (!refreshTokenValid) {
      throw new ForbiddenException('Access Denied!');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refresh_token);
    return tokens;
  }

  private async generateHash(data: string): Promise<string> {
    return await bcrypt.hash(data, 10);
  }

  private async getToken(payload: JwtPayload, options: TokenOptions) {
    return await this.jwtService.signAsync(payload, options);
  }

  private async getTokens(userId: number, email: string): Promise<Tokens> {
    const payload: JwtPayload = { sub: userId, email };
    const [accessToken, refreshToken] = await Promise.all([
      this.getToken(payload, {
        secret: 'at-secret',
        expiresIn: FIFTEEN_MINUTES,
      }),
      this.getToken(payload, {
        secret: 'rt-secret',
        expiresIn: ONE_WEEK,
      }),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  private async updateRefreshTokenHash(userId: number, refreshToken: string) {
    const hash = await this.generateHash(refreshToken);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRefreshToken: hash,
      },
    });
  }
}
