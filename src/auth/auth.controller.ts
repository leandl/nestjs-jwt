import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';

import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

import {
  GetCurrentUser,
  GetCurrentUserId,
  RequiredAccessToken,
  RequiredRefreshToken,
} from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() user: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(user);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() user: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(user);
  }

  @Post('logout')
  @RequiredAccessToken
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@GetCurrentUserId() userId: number) {
    this.authService.logout(userId);
  }

  @Post('refresh')
  @RequiredRefreshToken
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
