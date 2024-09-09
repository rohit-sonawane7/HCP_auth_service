// bullmq.module.ts
import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { BullQueueService } from './services/bullmq.service'

@Module({
  imports: [
    BullModule.forRoot({
      connection: {
        host: 'localhost',
        port: 6379,
      },
    }),
    BullModule.registerQueue({
      name: 'task-queue',
    }),
  ],
  providers: [BullQueueService],
  exports: [BullQueueService],
})
export class BullQueueModule { }
