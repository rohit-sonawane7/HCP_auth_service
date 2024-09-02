import { Controller, Post, Body, Res, HttpStatus, ValidationPipe } from '@nestjs/common';
import { AuthService } from '../services/authService';
import { RegisterDto, LoginDto } from '../dto/auth.dto';
import { LoggerService } from '../logger/logger';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly logger: LoggerService
  ) { }

  @Post('register')
  async register(
    @Body(new ValidationPipe()) registerDto: RegisterDto,
    @Res() res: Response
  ): Promise<void> {
    try {
      await this.authService.register(registerDto);
      this.logger.log('User registered successfully');
      res.status(HttpStatus.CREATED).json({ msg: 'User registered successfully' });
    } catch (err: any) {
      this.logger.error(`Error during registration: ${err.message}`, err.stack);
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({ message: err.message });
    }
  }

  @Post('login')
  async login(
    @Body(new ValidationPipe()) loginDto: LoginDto,
    @Res() res: Response
  ): Promise<void> {
    try {
      const token = await this.authService.login(loginDto);
      this.logger.log('User logged in successfully');
      res.status(HttpStatus.OK).json({ token });
    } catch (err: any) {
      this.logger.error(`Error during login: ${err.message}`, err.stack);
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).send({ message: err.message });
    }
  }
}
