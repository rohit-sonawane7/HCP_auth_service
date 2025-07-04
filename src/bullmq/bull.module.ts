import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { BullProcessor } from './bull.processor';

@Module({
  imports: [
    BullModule.forRoot({
      redis: {
        host: 'localhost',
        port: 6379,
      },
    }),
    BullModule.registerQueue({
      name: 'deleteUnverifiedUser',
    }),
  ],
  providers: [BullProcessor],
})
export class BullQueueModule {}
