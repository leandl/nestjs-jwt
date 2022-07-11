import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/local/signup')
  signupLocal(@Body() user: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(user);
  }

  @Post('/local/signin')
  signinLocal(@Body() user: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(user);
  }

  @Post('/local/logout')
  logout() {
    this.authService.logout();
  }

  @Post('/refresh')
  refreshTokens() {
    this.authService.refreshTokens();
  }
}
