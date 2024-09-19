import { Injectable, Inject, OnModuleInit } from '@nestjs/common';
import { Kafka, Producer, Consumer } from 'kafkajs';

@Injectable()
export class KafkaService implements OnModuleInit {
  private producer: Producer;
  private consumer: Consumer;

  constructor(@Inject('KAFKA_CONFIG') private kafkaConfig: { clientId: string, brokers: string[] }) { }

  async onModuleInit() {
    const kafka = new Kafka({
      clientId: this.kafkaConfig.clientId,
      brokers: this.kafkaConfig.brokers,
    });

    this.producer = kafka.producer();
    this.consumer = kafka.consumer({ groupId: `${this.kafkaConfig.clientId}-group` });

    await this.producer.connect();
    await this.consumer.connect();
  }

  // Send message to a Kafka topic
  async send(topic: string, message: any) {
    await this.producer.send({
      topic,
      messages: [{ value: JSON.stringify(message) }],
    });
  }

  // Subscribe and consume messages from a Kafka topic
  async consume(topic: string, callback: (message: any) => Promise<void>) {
    await this.consumer.subscribe({ topic });
    await this.consumer.run({
      eachMessage: async (message: any) => {
        const parsedMessage = JSON.parse(message.value.toString());
        await callback(parsedMessage);
      },
    });
  }

  async disconnect() {
    await this.producer.disconnect();
    await this.consumer.disconnect();
  }
}