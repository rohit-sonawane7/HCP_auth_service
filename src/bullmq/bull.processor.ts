import { Processor, Process } from '@nestjs/bull';
import { Job } from 'bull';
import { AuthService } from '../services/authService';

@Processor('deleteUnverifiedUser')
export class BullProcessor {
    constructor(private readonly authService: AuthService) { }

    @Process()
    async handleDeleteUser(job: Job) {
        const { email } = job.data;
        await this.authService.deleteUnverifiedUser(email);
    }
}
