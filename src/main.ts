import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import { HttpExceptionFilter } from './middlewares/errorHandler';
import { AppModule } from './app.module';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    app.setGlobalPrefix('api');
    app.enableCors();
    app.useGlobalFilters(new HttpExceptionFilter());
    await app.listen(3000);
    Logger.log('Application is running on: http://localhost:3000', 'Bootstrap');
}

bootstrap();
