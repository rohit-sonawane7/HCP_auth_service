import { Post, Body, Controller, ValidationPipe, UseFilters, HttpCode } from '@nestjs/common';
import { AuthService } from '../services/authService';
import { RegisterDto, LoginDto } from '../dto/auth.dto';
import { LoggerService } from '../logger/logger';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { HttpExceptionFilter } from '../middlewares/errorHandler';
import { LoginResponse, UserToken } from '../types/user';

@Controller('auth')
@UseFilters(HttpExceptionFilter)
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly logger: LoggerService
  ) { }

  @HttpCode(201)
  @Post('register')
  async register(
    @Body(new ValidationPipe()) registerDto: RegisterDto,
  ): Promise<void> {
    return this.authService.register(registerDto);
  }

  @HttpCode(200)
  @Post('login')
  async login(
    @Body(new ValidationPipe()) loginDto: LoginDto,
  ): Promise<LoginResponse> {
    return this.authService.login(loginDto);
  }

  @HttpCode(200)
  @Post('reset-password')
  async resetPassword(
    @Body(new ValidationPipe()) resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    return this.authService.resetPassword(resetPasswordDto);
  }

  @HttpCode(200)
  @Post('refresh-token')
  async refreshToken(
    @Body('refreshToken') refreshToken: string,
  ): Promise<UserToken> {
    return this.authService.refreshJwtToken(refreshToken);
  }
}
