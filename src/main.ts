import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);

    // Set global prefix for API routes (optional)
    app.setGlobalPrefix('api');

    // Enable CORS (optional, depending on your needs)
    app.enableCors();

    // Start listening for requests
    await app.listen(3000);
    Logger.log('Application is running on: http://localhost:3000', 'Bootstrap');
}

bootstrap();
