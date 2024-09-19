// import 'dotenv/config';
// import { Module } from '@nestjs/common';
// import { TypeOrmModule } from '@nestjs/typeorm';
// import { ConfigModule, ConfigService } from '@nestjs/config';
// import { ClientKafka, ClientsModule, Transport } from '@nestjs/microservices';
// import { Partitioners } from 'kafkajs';
// import { BullQueueModule } from './bullmq.module';
// import { AuthModule } from './auth.module';
// import { User } from './entity/User';
// import { Otp } from './entity/Otp';
// import { AuthController } from "./controllers/authController";
// import { AuthService } from './services/authService';
// import { AuthModule } from './auth/auth.module';
import { DatabaseRepositoryModule } from './database_repository/database_repository.module';

// @Module({
//     imports: [
//         ConfigModule.forRoot({
//             isGlobal: true,
//         }),
//         TypeOrmModule.forRoot({
//             type: 'postgres',
//             url: process.env.DATABASE_URL,
//             synchronize: true,
//             entities: [User, Otp],
//             migrations: ['src/migration'],
//         }),
//         TypeOrmModule.forFeature([User, Otp]),
//         ClientsModule.registerAsync([
//             {
//                 name: 'KAFKA_SERVICE',
//                 useFactory: async (configService: ConfigService) => ({
//                     transport: Transport.KAFKA,
//                     options: {
//                         client: {
//                             brokers: [configService.get<string>('KAFKA_BROKER')], // localhost:9002
//                         },
//                         producer: {
//                             createPartitioner: Partitioners.LegacyPartitioner,
//                         },
//                     },
//                 }),
//                 inject: [ConfigService],
//             },
//         ]),
//         AuthModule,
//         BullQueueModule,
//     ],
//     controllers: [AuthController],
//     providers: [AuthService, ClientKafka]
// })

// export class AppModule { }
