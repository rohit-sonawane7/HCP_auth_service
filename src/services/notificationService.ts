import { Injectable } from '@nestjs/common';
import { KafkaService } from './kafka.service';

@Injectable()
export class OtpService {
  constructor(private readonly kafkaService: KafkaService) { }

  async sendOtpEmail(email: string, otp: string) {
    const message = { email, otp };
    await this.kafkaService.send('email-notifications-topic', message);
    console.log('OTP email task sent to Kafka');
  }
}
