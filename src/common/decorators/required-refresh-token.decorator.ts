import { applyDecorators, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

export const RequiredRefreshToken = applyDecorators(
  UseGuards(AuthGuard('jwt-refresh')),
);
