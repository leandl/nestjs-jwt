import { applyDecorators, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

export const RequiredAccessToken = applyDecorators(UseGuards(AuthGuard('jwt')));
