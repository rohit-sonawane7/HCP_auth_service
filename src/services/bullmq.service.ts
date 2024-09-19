// bullmq.service.ts
import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue, Worker, Job } from 'bullmq';

@Injectable()
export class BullQueueService {
    private worker: Worker;

    constructor(@InjectQueue('task-queue') private readonly taskQueue: Queue) {
        this.processTasks();
    }

    async addTask(job_name: string, data: any, delay: number) {
        await this.taskQueue.add(job_name, data, { delay });
    }

    private processTasks() {
        this.worker = new Worker(
            'task-queue',
            async (job: Job) => {
                console.log('Processing task:', job.data);
                return job.data;
            },
            {
                connection: {
                    host: 'localhost',
                    port: 6379,
                },
            },
        );

        this.worker.on('completed', (job) => {
            console.log(`Job ${job.id} completed! Result:`, job.returnvalue);
        });

        this.worker.on('failed', (job: any, err: any) => {
            console.error(`Job ${job.id} failed with error ${err.message}`);
        });
    }
}
